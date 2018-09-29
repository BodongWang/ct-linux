/*
 * net/netfilter/nft_gen_flow_offload.c  Maintain flows(conntrack connections) offloaded to HW by TC
 *
 * Copyright (c) 2018 Lidong Jiang <jianglidong3@jd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/netfilter/nf_tables.h>
#include <net/ip.h> /* for ipv4 options. */
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_core.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nft_gen_flow_offload.h>



unsigned int nft_gen_flow_offload_net_id;
EXPORT_SYMBOL_GPL(nft_gen_flow_offload_net_id);

#ifdef NFT_GEN_FLOW_FUNC_DEBUG
#define NFT_GEN_FLOW_FUNC_ENTRY()       pr_debug("%s entry", __FUNCTION__)
#define NFT_GEN_FLOW_FUNC_EXIT()        pr_debug("%s done", __FUNCTION__)
#else
#define NFT_GEN_FLOW_FUNC_ENTRY()
#define NFT_GEN_FLOW_FUNC_EXIT()
#endif

struct nft_gen_flow_offload_net {
    struct nf_flowtable __rcu *flowtable;
};

static inline struct nft_gen_flow_offload_net *nft_gen_flow_offload_pernet(const struct net *net)
{
    return net_generic(net, nft_gen_flow_offload_net_id);
}



struct flow_offload_entry {
    struct flow_offload     flow;
    struct nf_conn          *ct;
    struct rcu_head         rcu_head;
    struct spinlock         dep_lock;
	struct list_head        deps;
};


static void
nft_gen_flow_offload_fill_dir(struct flow_offload *flow,
                                        struct nf_conn *ct,
                                        int ifindex,
                                        enum flow_offload_tuple_dir dir)
{
    struct flow_offload_tuple *ft = &flow->tuplehash[dir].tuple;
    struct nf_conntrack_tuple *ctt = &ct->tuplehash[dir].tuple;

    ft->dir = dir;

    switch (ctt->src.l3num) {
    case NFPROTO_IPV4:
        ft->src_v4 = ctt->src.u3.in;
        ft->dst_v4 = ctt->dst.u3.in;
        ft->mtu = 0;
        break;
    case NFPROTO_IPV6:
        ft->src_v6 = ctt->src.u3.in6;
        ft->dst_v6 = ctt->dst.u3.in6;
        ft->mtu = 0;
        break;
    }

    ft->l3proto = ctt->src.l3num;
    ft->l4proto = ctt->dst.protonum;
    ft->src_port = ctt->src.u.tcp.port;
    ft->dst_port = ctt->dst.u.tcp.port;

    ft->iifidx = ifindex;
    ft->oifidx = ifindex;
    ft->dst_cache = NULL;
}


static struct flow_offload *
nft_gen_flow_offload_alloc(struct nf_conn *ct, int zone_id, int private_data_len)
{
    struct flow_offload_entry *entry;
    struct flow_offload *flow;

    if (unlikely(nf_ct_is_dying(ct) ||
        !atomic_inc_not_zero(&ct->ct_general.use)))
        return NULL;

    entry = kzalloc((sizeof(*entry) + private_data_len), GFP_ATOMIC);
    if (!entry)
        goto err_ct_refcnt;

    flow = &entry->flow;

    entry->ct = ct;

    nft_gen_flow_offload_fill_dir(flow, ct, zone_id, FLOW_OFFLOAD_DIR_ORIGINAL);
    nft_gen_flow_offload_fill_dir(flow, ct, zone_id, FLOW_OFFLOAD_DIR_REPLY);

    INIT_LIST_HEAD(&entry->deps);
    spin_lock_init(&entry->dep_lock);

    return flow;

err_ct_refcnt:
    nf_ct_put(ct);

    return NULL;
}

static int
nft_gen_flow_offload_init(const struct net *net)
{
    struct nft_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    struct nf_flowtable *flowtable;

    NFT_GEN_FLOW_FUNC_ENTRY();

	flowtable = kzalloc(sizeof(*flowtable), GFP_KERNEL);

	nf_flow_table_init(flowtable);

    rcu_assign_pointer(gnet->flowtable, flowtable);

    NFT_GEN_FLOW_FUNC_EXIT();

    return nf_ct_netns_get((struct net*)net, NFPROTO_INET);
}

static inline void _flow_offload_debug_op(const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple * tuple, char * op)
{
    if (tuple->src.l3num == AF_INET) {
        pr_debug("%s offloaded Tuple(%pI4, %pI4, %d, %d, %d) zone id %d\n",
                op, &tuple->src.u3.in, &tuple->dst.u3.in,
                ntohs(tuple->src.u.all), ntohs(tuple->dst.u.all),
                tuple->dst.protonum, zone->id);
    } else {
        pr_debug("%s offloaded Tuple(%pI6, %pI6, %d, %d, %d) zone id %d\n",
                op, &tuple->src.u3.in6, &tuple->dst.u3.in6,
                ntohs(tuple->src.u.all), ntohs(tuple->dst.u.all),
                tuple->dst.protonum, zone->id);
    }
}

static int _flowtable_add_entry(const struct net *net, int zone_id,
            struct nf_conn *ct, struct flow_offload ** ret_flow)
{
    struct nft_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    struct nf_flowtable *flowtable;
    struct flow_offload *flow;
    int ret;

    flow = nft_gen_flow_offload_alloc(ct, zone_id, 0);
    if (!flow)
        goto err_flow_alloc;

    flow->flags |= FLOW_OFFLOAD_HW;

    rcu_read_lock();
    flowtable = rcu_dereference(gnet->flowtable);
    if (flowtable) {
        ret = flow_offload_add(flowtable, flow);
        if (ret < 0)
            goto err_flow_add;

        if (ret_flow)
            *ret_flow = flow;

        rcu_read_unlock();

        return ret;
    }

err_flow_add:
    rcu_read_unlock();
    pr_debug("%s: err_flow_add", __FUNCTION__);
    flow_offload_free(flow);
err_flow_alloc:
    pr_debug("%s: err_flow_alloc", __FUNCTION__);
    clear_bit(IPS_OFFLOAD_BIT, &ct->status);

    return -EINVAL;
}

static int _check_ct_status(struct nf_conn *ct)
{
    if (test_bit(IPS_HELPER_BIT, &ct->status))
        goto err_ct;

    if (test_and_set_bit(IPS_OFFLOAD_BIT, &ct->status))
        return -EEXIST;

    return 0;
err_ct:
    pr_debug("%s: err_ct", __FUNCTION__);
    return -EINVAL;
}

static inline void _ct_tuple_2_flow_tuple(const struct nf_conntrack_zone *zone,
                const struct nf_conntrack_tuple * ct_tuple,
                struct flow_offload_tuple *flow_tuple)
{
    if (ct_tuple->src.l3num == AF_INET)
    {
        flow_tuple->src_v4 = ct_tuple->src.u3.in;
        flow_tuple->dst_v4 = ct_tuple->dst.u3.in;
    }
    else
    {
        flow_tuple->src_v6 = ct_tuple->src.u3.in6;
        flow_tuple->dst_v6 = ct_tuple->dst.u3.in6;
    }

    flow_tuple->src_port = ct_tuple->src.u.all;
    flow_tuple->dst_port = ct_tuple->dst.u.all;

    flow_tuple->l3proto = ct_tuple->src.l3num;
    flow_tuple->l4proto = ct_tuple->dst.protonum;

    flow_tuple->iifidx = zone->id;
}

static inline struct flow_offload_tuple_rhash *
_flowtable_lookup(const struct net *net,
                const struct nf_conntrack_zone *zone,
                const struct nf_conntrack_tuple * tuple)
{
    struct nft_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    struct flow_offload_tuple_rhash *tuplehash;
    struct nf_flowtable *flowtable;
    struct flow_offload_tuple flow_tuple = {};

    _ct_tuple_2_flow_tuple(zone, tuple, &flow_tuple);

    rcu_read_lock();

    flowtable = rcu_dereference(gnet->flowtable);
    if (flowtable) {
        tuplehash = flow_offload_lookup(flowtable, &flow_tuple);
        if (tuplehash == NULL) {
            pr_debug("%s: no hit ", __FUNCTION__);
        }
    }

    rcu_read_unlock();

    return tuplehash;
}


int nft_gen_flow_offload_add_in_skb(const struct net *net,
            const struct nf_conntrack_zone *zone, struct sk_buff *skb)
{
    struct nft_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct;
    int ret = -EINVAL;

    NFT_GEN_FLOW_FUNC_ENTRY();

    if (rcu_access_pointer(gnet->flowtable) == NULL)
        return -ENOENT;

    ct = nf_ct_get(skb, &ctinfo);
    if (!ct)
        return ret;

    ret = _check_ct_status(ct);
    if (ret == 0)
        ret = _flowtable_add_entry(net, zone->id, ct, NULL);

    NFT_GEN_FLOW_FUNC_EXIT();

    return ret;
}


EXPORT_SYMBOL_GPL(nft_gen_flow_offload_add_in_skb);

int nft_gen_flow_offload_add(const struct net *net,
            const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple * tuple)
{
    struct nft_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    const struct nf_conntrack_tuple_hash *thash;
    struct nf_conn *ct;
    int ret = -EINVAL;

    NFT_GEN_FLOW_FUNC_ENTRY();

    if (rcu_access_pointer(gnet->flowtable) == NULL)
        return -ENOENT;

    _flow_offload_debug_op(zone, tuple, "Add");

    thash = nf_conntrack_find_get((struct net *)net, zone, tuple);
    if (!thash)
        return -EINVAL;

    ct = nf_ct_tuplehash_to_ctrack(thash);

    ret = _check_ct_status(ct);
    if (ret == 0)
        ret = _flowtable_add_entry(net, zone->id, ct, NULL);

    nf_ct_put(ct);

    NFT_GEN_FLOW_FUNC_EXIT();

    return ret;
}


EXPORT_SYMBOL_GPL(nft_gen_flow_offload_add);



int nft_gen_flow_offload_expiration(const struct net *net,
                const struct nf_conntrack_zone *zone,
                const struct nf_conntrack_tuple *tuple)
{
    struct nft_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    struct flow_offload_tuple_rhash *tuplehash;
    struct flow_offload *flow;
    enum flow_offload_tuple_dir dir;

    NFT_GEN_FLOW_FUNC_ENTRY();

    if (rcu_access_pointer(gnet->flowtable) == NULL)
        return 0;

    _flow_offload_debug_op(zone, tuple, "Expire");

    tuplehash = _flowtable_lookup(net, zone, tuple);
    if (tuplehash) {
        dir = tuplehash->tuple.dir;
        flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);

        /* Can't use flow_teardown, flow_teardown should be 
           called before FIN is put into NF, it tries to restore 
           connection timeout value and seq */
    	flow->flags |= FLOW_OFFLOAD_TEARDOWN;
    }

    NFT_GEN_FLOW_FUNC_EXIT();
    return 0;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_expiration);



static struct flow_offload_dep_ops *flow_dep_ops = NULL;

void nft_gen_flow_offload_dep_ops_register(struct flow_offload_dep_ops * ops)
{
    flow_dep_ops = ops;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_dep_ops_register);


void nft_gen_flow_offload_dep_ops_unregister(struct flow_offload_dep_ops * ops)
{
    flow_dep_ops = NULL;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_dep_ops_unregister);


int nft_gen_flow_offload_add_dep(const struct net *net,
            const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple *tuple, void *dep)
{
    struct nft_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    const struct nf_conntrack_tuple_hash *thash;
    struct flow_offload_tuple_rhash *fhash;
    enum flow_offload_tuple_dir dir;
    struct flow_offload *flow;
    struct flow_offload_entry *entry;
    struct nf_conn *ct;
    int ret;

    NFT_GEN_FLOW_FUNC_ENTRY();

    if (!flow_dep_ops)
        return -EPERM;

    if (rcu_access_pointer(gnet->flowtable) == NULL)
        return -ENOENT;

    _flow_offload_debug_op(zone, tuple, "Add_Dep");

    /* lookup */
    fhash = _flowtable_lookup(net, zone, tuple);
    if (fhash) {
        dir = fhash->tuple.dir;
        entry = container_of(fhash, struct flow_offload_entry, flow.tuplehash[dir]);
    } else {
        thash = nf_conntrack_find_get((struct net *)net, zone, tuple);
        if (!thash)
            return -EINVAL;

        ct = nf_ct_tuplehash_to_ctrack(thash);

        ret = _check_ct_status(ct);
        if (ret ==  0) {
            ret = _flowtable_add_entry(net, zone->id, ct, &flow);
        }

        nf_ct_put(ct);
        if (ret < 0) return ret;

        entry = container_of(flow, struct flow_offload_entry, flow);
    }

    spin_lock(&entry->dep_lock);

    ret = flow_dep_ops->add(dep, &entry->deps);
    if (ret && (list_empty_careful(&entry->deps)))
        entry->flow.flags |= FLOW_OFFLOAD_TEARDOWN;

    spin_unlock(&entry->dep_lock);

    NFT_GEN_FLOW_FUNC_EXIT();

    return ret;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_add_dep);

int nft_gen_flow_offload_delete_dep(const struct net *net,
            const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple * tuple, void *dep)
{
    struct nft_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    struct flow_offload_tuple_rhash *fhash;
    enum flow_offload_tuple_dir dir;
    struct flow_offload_entry *entry;
    int ret;

    NFT_GEN_FLOW_FUNC_ENTRY();

    if (!flow_dep_ops)
        return -EPERM;

    if (rcu_access_pointer(gnet->flowtable) == NULL)
        return -ENOENT;

    _flow_offload_debug_op(zone, tuple, "Del_dep");

    /* lookup */
    fhash = _flowtable_lookup(net, zone, tuple);
    if (fhash) {
        dir = fhash->tuple.dir;
        entry = container_of(fhash, struct flow_offload_entry, flow.tuplehash[dir]);

        spin_lock(&entry->dep_lock);

        flow_dep_ops->remove(dep, &entry->deps);
        if (list_empty_careful(&entry->deps)) {
            entry->flow.flags |= FLOW_OFFLOAD_TEARDOWN;
        }
        spin_unlock(&entry->dep_lock);

    } else {
        ret = -ENOENT;
    }


    NFT_GEN_FLOW_FUNC_EXIT();

    return ret;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_delete_dep);


int nft_gen_flow_offload_remove(const struct net *net,
            const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple * tuple)
{
    struct nft_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    struct flow_offload_tuple_rhash *tuplehash;
    struct flow_offload_entry *entry;
    enum flow_offload_tuple_dir dir;
    struct list_head tmp;

    NFT_GEN_FLOW_FUNC_ENTRY();

    if (rcu_access_pointer(gnet->flowtable) == NULL)
        return 0;

    _flow_offload_debug_op(zone, tuple, "Remove");

    tuplehash = _flowtable_lookup(net, zone, tuple);
    if (tuplehash != NULL) {
        dir = tuplehash->tuple.dir;
        
        entry = container_of(tuplehash, struct flow_offload_entry, flow.tuplehash[dir]);
                
        entry->flow.flags |= FLOW_OFFLOAD_TEARDOWN;

        if (flow_dep_ops) {
            
            spin_lock(&entry->dep_lock);
            list_replace(&entry->deps, &tmp);
            INIT_LIST_HEAD(&entry->deps);
            spin_unlock(&entry->dep_lock);

            flow_dep_ops->destroy(&tmp);
        }
    }

    NFT_GEN_FLOW_FUNC_EXIT();

    return 0;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_remove);


static void nft_gen_flow_table_do_cleanup(struct flow_offload *flow, void *data)
{
    int *zone_id = data;
    NFT_GEN_FLOW_FUNC_ENTRY();

    if (!zone_id) {
        flow->flags &= ~FLOW_OFFLOAD_HW;
        flow->flags |= FLOW_OFFLOAD_TEARDOWN;
        return;
    }

    if (flow->tuplehash[0].tuple.iifidx == *zone_id ||
        flow->tuplehash[1].tuple.iifidx == *zone_id) {
        flow->flags &= ~FLOW_OFFLOAD_HW;
        flow_offload_dead(flow);
    }
}



static int __net_init nft_gen_flow_net_init(struct net *net)
{
    struct nft_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);

    pr_debug("nft_gen_flow_net_init: net %p", net);

    rcu_assign_pointer(gnet->flowtable, NULL);

    nft_gen_flow_offload_init(net);

#if 0
    // for debug only
    {
        struct nf_conntrack_tuple test_tuple;
        struct nf_conntrack_zone test_zone = {NF_CT_DEFAULT_ZONE_ID, 0, NF_CT_DEFAULT_ZONE_DIR};

        memset(&test_tuple, 0, sizeof(test_tuple));

        test_tuple.src.u3.ip = htonl(0xc0a86e01);
        test_tuple.src.u.tcp.port = htons(51171);
        test_tuple.src.l3num = AF_INET;

        test_tuple.dst.u3.ip = htonl(0xc0a86e84);
        test_tuple.dst.u.tcp.port = htons(22);
        test_tuple.dst.protonum = IPPROTO_TCP;
        test_tuple.dst.dir = NF_CT_ZONE_DIR_ORIG;

        nft_gen_flow_offload_add(net, &test_zone, &test_tuple);

        nft_gen_flow_offload_remove(net, &test_zone, &test_tuple);
    }
#endif
    return 0;
}

static void __net_exit nft_gen_flow_net_exit(struct net *net)
{
    struct nft_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    struct nf_flowtable * flowtable = rcu_access_pointer(gnet->flowtable);

    if (flowtable != NULL) {
        rcu_assign_pointer(gnet->flowtable, NULL);

        synchronize_rcu();

        nf_flow_table_iterate(flowtable, nft_gen_flow_table_do_cleanup, NULL);

        nf_flow_table_free(flowtable);

        kfree(flowtable);

        nf_ct_netns_put((struct net*)net, NFPROTO_INET);
    }
}


static struct pernet_operations nft_gen_flow_offload_net_ops = {
    .init           = nft_gen_flow_net_init,
    .exit           = nft_gen_flow_net_exit, // TODO: change to batch
    .id             = &nft_gen_flow_offload_net_id,
    .size           = sizeof(struct nft_gen_flow_offload_net),
};


static int __init nft_gen_flow_offload_module_init(void)
{
    int err;

    err = register_pernet_subsys(&nft_gen_flow_offload_net_ops);
    if (err < 0)
        return err;

    return 0;
}



static void __exit nft_gen_flow_offload_module_exit(void)
{
    unregister_pernet_subsys(&nft_gen_flow_offload_net_ops);
}

module_init(nft_gen_flow_offload_module_init);
module_exit(nft_gen_flow_offload_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lidong Jiang <jianglidong3@jd.com>");
