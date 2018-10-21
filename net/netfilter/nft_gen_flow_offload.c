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
#include <linux/rhashtable.h>
#include <net/ip.h> /* for ipv4 options. */

#include <net/netfilter/nf_conntrack_core.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <net/netfilter/nft_gen_flow_offload.h>


#ifdef NFT_GEN_FLOW_FUNC_DEBUG
#define NFT_GEN_FLOW_FUNC_ENTRY()       pr_debug("%s entry", __FUNCTION__)
#define NFT_GEN_FLOW_FUNC_EXIT()        pr_debug("%s done", __FUNCTION__)
#else
#define NFT_GEN_FLOW_FUNC_ENTRY()
#define NFT_GEN_FLOW_FUNC_EXIT()
#endif


unsigned int nft_gen_flow_offload_net_id;
EXPORT_SYMBOL_GPL(nft_gen_flow_offload_net_id);


struct nf_gen_flow_offload_net {
    struct nf_gen_flow_offload_table __rcu *flowtable;
};

static inline struct nf_gen_flow_offload_net *nft_gen_flow_offload_pernet(const struct net *net)
{
    return net_generic(net, nft_gen_flow_offload_net_id);
}

static unsigned int offloaded_ct_timeout = 30*HZ;

module_param(offloaded_ct_timeout, uint, 0644);

#define PORTING_FLOW_TABLE

#ifdef PORTING_FLOW_TABLE



struct nf_gen_flow_offload_table {
	struct list_head		list;
	struct rhashtable		rhashtable;
	struct delayed_work		gc_work;
};

enum nf_gen_flow_offload_tuple_dir {
	FLOW_OFFLOAD_DIR_ORIGINAL = IP_CT_DIR_ORIGINAL,
	FLOW_OFFLOAD_DIR_REPLY = IP_CT_DIR_REPLY,
	FLOW_OFFLOAD_DIR_MAX = IP_CT_DIR_MAX
};


struct nf_gen_flow_offload_tuple_rhash {
	struct rhash_head		node;
	struct nf_conntrack_tuple	tuple;
	struct nf_conntrack_zone    zone; // TODO: FIXME, less memory footprint
};



#define FLOW_OFFLOAD_DYING	    0x1
#define FLOW_OFFLOAD_TEARDOWN	0x2
#define FLOW_OFFLOAD_AGING      0x4
#define FLOW_OFFLOAD_EXPIRED    0x8

struct nf_gen_flow_offload {
	struct nf_gen_flow_offload_tuple_rhash		tuplehash[FLOW_OFFLOAD_DIR_MAX];
	u32	    flags;
	u64		timeout;
};


struct nf_gen_flow_offload_entry {
    struct nf_gen_flow_offload     flow;
    struct nf_conn          *ct;
    struct rcu_head         rcu_head;
    struct spinlock         dep_lock; // FIXME, narrow down spin_lock, don't call user callback with locked.
	struct list_head        deps;
	struct nf_gen_flow_ct_stat stats;
};

static int nft_gen_flow_offload_stats(struct nf_gen_flow_offload *flow);
static int nft_gen_flow_offload_destroy_dep(struct nf_gen_flow_offload *flow);


static void
nf_gen_flow_offload_fill_dir(struct nf_gen_flow_offload *flow,
                                        struct nf_conn *ct,
                                        int zone_id,
                                        enum nf_gen_flow_offload_tuple_dir dir)
{
    flow->tuplehash[dir].tuple = ct->tuplehash[dir].tuple;
    flow->tuplehash[dir].tuple.dst.dir = dir;

    flow->tuplehash[dir].zone.id = zone_id;
}


static struct nf_gen_flow_offload *
nf_gen_flow_offload_alloc(struct nf_conn *ct, int zone_id, int private_data_len)
{
    struct nf_gen_flow_offload_entry *entry;
    struct nf_gen_flow_offload *flow;

    if (unlikely(nf_ct_is_dying(ct) ||
        !atomic_inc_not_zero(&ct->ct_general.use)))
        return NULL;

    entry = kzalloc((sizeof(*entry) + private_data_len), GFP_ATOMIC);
    if (!entry)
        goto err_ct_refcnt;

    flow = &entry->flow;

    entry->ct = ct;

    nf_gen_flow_offload_fill_dir(flow, ct, zone_id, FLOW_OFFLOAD_DIR_ORIGINAL);
    nf_gen_flow_offload_fill_dir(flow, ct, zone_id, FLOW_OFFLOAD_DIR_REPLY);

    INIT_LIST_HEAD(&entry->deps);
    spin_lock_init(&entry->dep_lock);

    return flow;

err_ct_refcnt:
    nf_ct_put(ct);

    return NULL;
}

static void nf_gen_flow_offload_fixup_tcp(struct ip_ct_tcp *tcp)
{
	tcp->state = TCP_CONNTRACK_ESTABLISHED;
	tcp->seen[0].td_maxwin = 0;
	tcp->seen[1].td_maxwin = 0;
}

static void nf_gen_flow_offload_fixup_ct_state(struct nf_conn *ct)
{
	const struct nf_conntrack_l4proto *l4proto;
	struct net *net = nf_ct_net(ct);
	unsigned int *timeouts;
	unsigned int timeout;
	int l4num;

	l4num = nf_ct_protonum(ct);
	if (l4num == IPPROTO_TCP)
		nf_gen_flow_offload_fixup_tcp(&ct->proto.tcp);

	l4proto = __nf_ct_l4proto_find(nf_ct_l3num(ct), l4num);
	if (!l4proto)
		return;

	timeouts = l4proto->get_timeouts(net);
	if (!timeouts)
		return;

	if (l4num == IPPROTO_TCP)
		timeout = timeouts[TCP_CONNTRACK_ESTABLISHED];
	else if (l4num == IPPROTO_UDP)
		timeout = timeouts[UDP_CT_REPLIED];
	else
		return;

	ct->timeout = nfct_time_stamp + timeout;
}

void nf_gen_flow_offload_free(struct nf_gen_flow_offload *flow)
{
	struct nf_gen_flow_offload_entry *e;

	e = container_of(flow, struct nf_gen_flow_offload_entry, flow);
	if (flow->flags & FLOW_OFFLOAD_DYING)
		nf_ct_delete(e->ct, 0, 0);
	nf_ct_put(e->ct);
	kfree_rcu(e, rcu_head);
}

static u32 _flow_offload_hash(const void *data, u32 len, u32 seed)
{
	const struct nf_conntrack_tuple *tuple = data;
	unsigned int n;

	n = (sizeof(tuple->src) + sizeof(tuple->dst.u3)) / sizeof(u32);

    /* reuse nf_conntrack hash method */
	return jhash2((u32 *)tuple, n, seed ^
		      (((__force __u16)tuple->dst.u.all << 16) |
		      tuple->dst.protonum));
}

static u32 _flow_offload_hash_obj(const void *data, u32 len, u32 seed)
{
	const struct nf_gen_flow_offload_tuple_rhash *tuplehash = data;
	unsigned int n;

	n = (sizeof(tuplehash->tuple.src) + sizeof(tuplehash->tuple.dst.u3)) / sizeof(u32);

	return jhash2((u32 *)&tuplehash->tuple, n, seed ^
		      (((__force __u16)tuplehash->tuple.dst.u.all << 16) |
		      tuplehash->tuple.dst.protonum));
}

static int _flow_offload_hash_cmp(struct rhashtable_compare_arg *arg,
					const void *ptr)
{
	const struct nf_gen_flow_offload_tuple_rhash *x = ptr;
	struct nf_gen_flow_offload_tuple_rhash *thash;

	thash = container_of(arg->key, struct nf_gen_flow_offload_tuple_rhash, tuple);

	if (memcmp(&x->tuple, &thash->tuple, offsetof(struct nf_conntrack_tuple, dst.dir)) ||
	    (x->zone.id != thash->zone.id))
		return 1;

	return 0;
}

static const struct rhashtable_params nf_gen_flow_offload_rhash_params = {
	.head_offset		= offsetof(struct nf_gen_flow_offload_tuple_rhash, node),
	.hashfn			= _flow_offload_hash,
	.obj_hashfn		= _flow_offload_hash_obj,
	.obj_cmpfn		= _flow_offload_hash_cmp,
	.automatic_shrinking	= true,
};

static int nf_gen_flow_offload_add(struct nf_gen_flow_offload_table *flow_table,
                                                struct nf_gen_flow_offload *flow)
{
	rhashtable_insert_fast(&flow_table->rhashtable,
			       &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].node,
			       nf_gen_flow_offload_rhash_params);
	rhashtable_insert_fast(&flow_table->rhashtable,
			       &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].node,
			       nf_gen_flow_offload_rhash_params);
	return 0;
}

static void nf_gen_flow_offload_del(struct nf_gen_flow_offload_table *flow_table,
			     struct nf_gen_flow_offload *flow)
{
	struct nf_gen_flow_offload_entry *e;

	rhashtable_remove_fast(&flow_table->rhashtable,
			       &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].node,
			       nf_gen_flow_offload_rhash_params);
	rhashtable_remove_fast(&flow_table->rhashtable,
			       &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].node,
			       nf_gen_flow_offload_rhash_params);

	e = container_of(flow, struct nf_gen_flow_offload_entry, flow);
	clear_bit(IPS_OFFLOAD_BIT, &e->ct->status);

    // TODO: FIXME
	nft_gen_flow_offload_destroy_dep(flow);

	nf_gen_flow_offload_free(flow);
}

void nf_gen_flow_offload_teardown(struct nf_gen_flow_offload *flow)
{
	struct nf_gen_flow_offload_entry *e;

	flow->flags |= FLOW_OFFLOAD_TEARDOWN;

	e = container_of(flow, struct nf_gen_flow_offload_entry, flow);
	nf_gen_flow_offload_fixup_ct_state(e->ct);
}

static struct nf_gen_flow_offload_tuple_rhash *
nf_gen_flow_offload_lookup(struct nf_gen_flow_offload_table *flow_table,
                                        const struct nf_conntrack_zone *zone,
                            		    const struct nf_conntrack_tuple *tuple)
{
	struct nf_gen_flow_offload_tuple_rhash key, *res;
	struct nf_gen_flow_offload *flow;
	int dir;

    key.tuple = *tuple;
    key.zone  = *zone;

	res = rhashtable_lookup_fast(&flow_table->rhashtable, &key.tuple,
					   nf_gen_flow_offload_rhash_params);
	if (!res)
		return NULL;

	dir = res->tuple.dst.dir;
	flow = container_of(res, struct nf_gen_flow_offload, tuplehash[dir]);
	if (flow->flags & (FLOW_OFFLOAD_DYING | FLOW_OFFLOAD_TEARDOWN))
		return NULL;

	return res;
}

int nf_gen_flow_offload_table_iterate(struct nf_gen_flow_offload_table *flow_table,
			  void (*iter)(struct nf_gen_flow_offload *flow, void *data),
			  void *data)
{
	struct nf_gen_flow_offload_tuple_rhash *tuplehash;
	struct rhashtable_iter hti;
	struct nf_gen_flow_offload *flow;
	int err;

	err = rhashtable_walk_init(&flow_table->rhashtable, &hti, GFP_KERNEL);
	if (err)
		return err;

	rhashtable_walk_start(&hti);

	while ((tuplehash = rhashtable_walk_next(&hti))) {
		if (IS_ERR(tuplehash)) {
			err = PTR_ERR(tuplehash);
			if (err != -EAGAIN)
				goto out;

			continue;
		}
		if (tuplehash->tuple.dst.dir)
			continue;

		flow = container_of(tuplehash, struct nf_gen_flow_offload, tuplehash[0]);

		iter(flow, data);
	}
out:
	rhashtable_walk_stop(&hti);
	rhashtable_walk_exit(&hti);

	return err;
}


static inline bool nf_gen_flow_offload_has_expired(const struct nf_gen_flow_offload *flow)
{
    return (((flow->flags & (FLOW_OFFLOAD_AGING | FLOW_OFFLOAD_DYING | FLOW_OFFLOAD_TEARDOWN))
                == FLOW_OFFLOAD_AGING) && (flow->timeout <= jiffies));
}

static inline void nf_gen_flow_offload_set_aging(struct nf_gen_flow_offload *flow)
{
    flow->flags |= FLOW_OFFLOAD_AGING;
}



static int nf_gen_flow_offload_gc_step(struct nf_gen_flow_offload_table *flow_table)
{
	struct nf_gen_flow_offload_tuple_rhash *tuplehash;
	struct rhashtable_iter hti;
	struct nf_gen_flow_offload *flow;
	int err;

	err = rhashtable_walk_init(&flow_table->rhashtable, &hti, GFP_KERNEL);
	if (err)
		return 0;

	rhashtable_walk_start(&hti);

	while ((tuplehash = rhashtable_walk_next(&hti))) {
		if (IS_ERR(tuplehash)) {
			err = PTR_ERR(tuplehash);
			if (err != -EAGAIN)
				goto out;

			continue;
		}
		if (tuplehash->tuple.dst.dir)
			continue;

		flow = container_of(tuplehash, struct nf_gen_flow_offload, tuplehash[0]);

        if (nf_gen_flow_offload_has_expired(flow)) {
            nft_gen_flow_offload_stats(flow);

            if (nf_gen_flow_offload_has_expired(flow)) {
                flow->flags |= FLOW_OFFLOAD_TEARDOWN;
            }
        }

        if (flow->flags & (FLOW_OFFLOAD_DYING |
                        FLOW_OFFLOAD_TEARDOWN))
            nf_gen_flow_offload_del(flow_table, flow);
	}
out:
	rhashtable_walk_stop(&hti);
	rhashtable_walk_exit(&hti);

	return 1;
}

static void nf_gen_flow_offload_work_gc(struct work_struct *work)
{
	struct nf_gen_flow_offload_table *flow_table;

	flow_table = container_of(work, struct nf_gen_flow_offload_table, gc_work.work);
	nf_gen_flow_offload_gc_step(flow_table);
	queue_delayed_work(system_power_efficient_wq, &flow_table->gc_work, HZ);
}

int nf_gen_flow_offload_table_init(struct nf_gen_flow_offload_table *flowtable)
{
	int err;

	INIT_DEFERRABLE_WORK(&flowtable->gc_work, nf_gen_flow_offload_work_gc);

	err = rhashtable_init(&flowtable->rhashtable,
			      &nf_gen_flow_offload_rhash_params);
	if (err < 0)
		return err;

	queue_delayed_work(system_power_efficient_wq,
			   &flowtable->gc_work, HZ);

	return 0;
}

static inline void nf_gen_flow_offload_dead(struct nf_gen_flow_offload *flow)
{
	flow->flags |= FLOW_OFFLOAD_DYING;
}

/*  TO be changed */
static void nf_gen_flow_offload_table_do_cleanup(struct nf_gen_flow_offload *flow, void *data)
{
	nf_gen_flow_offload_dead(flow);
}



void nf_gen_flow_offload_table_free(struct nf_gen_flow_offload_table *flow_table)
{
	cancel_delayed_work_sync(&flow_table->gc_work);
	nf_gen_flow_offload_table_iterate(flow_table, nf_gen_flow_offload_table_do_cleanup, NULL);
	WARN_ON(!nf_gen_flow_offload_gc_step(flow_table));
	rhashtable_destroy(&flow_table->rhashtable);
}


#endif

static struct flow_offload_dep_ops *flow_dep_ops = NULL;

static inline void _flow_offload_debug_op(const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple * tuple, char * op)
{
    if (tuple->src.l3num == AF_INET) {
        pr_debug("%s Tuple(%pI4, %pI4, %d, %d, %d) zone id %d\n",
                op, &tuple->src.u3.in, &tuple->dst.u3.in,
                ntohs(tuple->src.u.all), ntohs(tuple->dst.u.all),
                tuple->dst.protonum, zone->id);
    } else {
        pr_debug("%s Tuple(%pI6, %pI6, %d, %d, %d) zone id %d\n",
                op, &tuple->src.u3.in6, &tuple->dst.u3.in6,
                ntohs(tuple->src.u.all), ntohs(tuple->dst.u.all),
                tuple->dst.protonum, zone->id);
    }
}

static int _flowtable_add_entry(const struct net *net, int zone_id,
            struct nf_conn *ct, struct nf_gen_flow_offload ** ret_flow)
{
    struct nf_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    struct nf_gen_flow_offload_table *flowtable;
    struct nf_gen_flow_offload *flow;
    int ret;

    flow = nf_gen_flow_offload_alloc(ct, zone_id, 0);
    if (!flow)
        goto err_flow_alloc;

    rcu_read_lock();
    flowtable = rcu_dereference(gnet->flowtable);
    if (flowtable) {
        ret = nf_gen_flow_offload_add(flowtable, flow);
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
    nf_gen_flow_offload_free(flow);
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

// TODO: remove this wrapper
static inline struct nf_gen_flow_offload_tuple_rhash *
_flowtable_lookup(const struct net *net,
                const struct nf_conntrack_zone *zone,
                const struct nf_conntrack_tuple *tuple)
{
    struct nf_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    struct nf_gen_flow_offload_table *flowtable;
    struct nf_gen_flow_offload_tuple_rhash *tuplehash = NULL;

    rcu_read_lock();

    flowtable = rcu_dereference(gnet->flowtable);
    if (flowtable) {
        tuplehash = nf_gen_flow_offload_lookup(flowtable, zone, tuple);
        if (tuplehash == NULL) {
            pr_debug("%s: no hit ", __FUNCTION__);
        }
    }

    rcu_read_unlock();

    return tuplehash;
}


/* retrieve stats by callbacks */
static int nft_gen_flow_offload_stats(struct nf_gen_flow_offload *flow)
{
    struct nf_gen_flow_offload_entry *e;
    u64 last_used;

    e = container_of(flow, struct nf_gen_flow_offload_entry, flow);

    /* retrieve stats by callbacks */
    spin_lock(&e->dep_lock);
    last_used = e->stats.last_used;
    flow_dep_ops->get_stats(&e->stats, &e->deps);
    spin_unlock(&e->dep_lock);

    /* update timeout with new last_used value, last_used is set as jiffies in drv;
       When TCP is disconnected by FIN, conntrack conneciton may be held by IPS_OFFLOAD
       until it is unset */

    if (e->stats.last_used > last_used)
        flow->timeout = e->stats.last_used + offloaded_ct_timeout;
    
    return 0;
}

/* connection is aged out, notify all dependencies  */
static int nft_gen_flow_offload_destroy_dep(struct nf_gen_flow_offload *flow)
{
    struct nf_gen_flow_offload_entry *e;
    struct list_head tmp;

	e = container_of(flow, struct nf_gen_flow_offload_entry, flow);

    if ((flow_dep_ops) && flow_dep_ops->destroy) {

        INIT_LIST_HEAD(&tmp);

        spin_lock(&e->dep_lock);
        list_replace_init(&e->deps, &tmp);
        spin_unlock(&e->dep_lock);

        flow_dep_ops->destroy(&tmp);
    }

    return 0;
}


/* EXPORT FUNCTIONS */

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



int nft_gen_flow_offload_add(const struct net *net,
            const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple *tuple, void *dep)
{
    struct nf_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    const struct nf_conntrack_tuple_hash *thash;
    struct nf_gen_flow_offload_tuple_rhash *fhash;
    enum nf_gen_flow_offload_tuple_dir dir;
    struct nf_gen_flow_offload *flow;
    struct nf_gen_flow_offload_entry *entry;
    struct nf_conn *ct;
    int ret;

    NFT_GEN_FLOW_FUNC_ENTRY();

    if (!flow_dep_ops)
        return -EPERM;

    if (rcu_access_pointer(gnet->flowtable) == NULL)
        return -ENOENT;

    _flow_offload_debug_op(zone, tuple, "Add");

    /* lookup */
    fhash = _flowtable_lookup(net, zone, tuple);
    if (fhash) {
        dir = fhash->tuple.dst.dir;
        entry = container_of(fhash, struct nf_gen_flow_offload_entry, flow.tuplehash[dir]);
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

        entry = container_of(flow, struct nf_gen_flow_offload_entry, flow);
    }

    if (flow_dep_ops->add) {
        spin_lock(&entry->dep_lock);

        /* checking if it was destroyed before we got spin lock*/
        if (entry->flow.flags & (FLOW_OFFLOAD_TEARDOWN | 
                                    FLOW_OFFLOAD_DYING)) {
            spin_unlock(&entry->dep_lock);
            return -EINVAL;
        }

        ret = flow_dep_ops->add(dep, &entry->deps);
        if (ret && (list_empty_careful(&entry->deps))) {
            entry->flow.flags |= FLOW_OFFLOAD_TEARDOWN;
            spin_unlock(&entry->dep_lock);
            return ret;
        }

        spin_unlock(&entry->dep_lock);
    }

    if (flow_dep_ops->get_stats) {
        /* update timeout for new dep*/
        entry->flow.timeout = jiffies + offloaded_ct_timeout;

        nf_gen_flow_offload_set_aging(&entry->flow);
    }

    NFT_GEN_FLOW_FUNC_EXIT();

    return ret;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_add);

int nft_gen_flow_offload_remove(const struct net *net,
            const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple * tuple, void *dep)
{
    struct nf_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    struct nf_gen_flow_offload_tuple_rhash *fhash;
    enum nf_gen_flow_offload_tuple_dir dir;
    struct nf_gen_flow_offload_entry *entry;
    int ret;

    NFT_GEN_FLOW_FUNC_ENTRY();

    if (!flow_dep_ops)
        return -EPERM;

    if (rcu_access_pointer(gnet->flowtable) == NULL)
        return -ENOENT;

    _flow_offload_debug_op(zone, tuple, "Rmv");

    /* lookup */
    fhash = _flowtable_lookup(net, zone, tuple);
    if (fhash) {
        dir = fhash->tuple.dst.dir;
        entry = container_of(fhash, struct nf_gen_flow_offload_entry, flow.tuplehash[dir]);

        if (flow_dep_ops->remove) {
            spin_lock(&entry->dep_lock);

            flow_dep_ops->remove(dep, &entry->deps);
            if (list_empty_careful(&entry->deps)) {
                entry->flow.flags |= FLOW_OFFLOAD_TEARDOWN;
            }
            spin_unlock(&entry->dep_lock);
        }
    } else {
        ret = -ENOENT;
    }


    NFT_GEN_FLOW_FUNC_EXIT();

    return ret;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_remove);


int nft_gen_flow_offload_destroy(const struct net *net,
            const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple * tuple)
{
    struct nf_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    struct nf_gen_flow_offload_tuple_rhash *thash;
    struct nf_gen_flow_offload *flow;
    enum nf_gen_flow_offload_tuple_dir dir;

    NFT_GEN_FLOW_FUNC_ENTRY();

    if (rcu_access_pointer(gnet->flowtable) == NULL)
        return 0;

    _flow_offload_debug_op(zone, tuple, "Destroy");

    thash = _flowtable_lookup(net, zone, tuple);
    if (thash != NULL) {
        dir = thash->tuple.dst.dir;

        flow = container_of(thash, struct nf_gen_flow_offload, tuplehash[dir]);

        nft_gen_flow_offload_destroy_dep(flow);

        flow->flags |= FLOW_OFFLOAD_TEARDOWN;
    }

    NFT_GEN_FLOW_FUNC_EXIT();

    return 0;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_destroy);


static int
nft_gen_flow_offload_init(const struct net *net)
{
    struct nf_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    struct nf_gen_flow_offload_table *flowtable;

    NFT_GEN_FLOW_FUNC_ENTRY();

	flowtable = kzalloc(sizeof(*flowtable), GFP_KERNEL);

	nf_gen_flow_offload_table_init(flowtable);

    rcu_assign_pointer(gnet->flowtable, flowtable);

    NFT_GEN_FLOW_FUNC_EXIT();

    return 0;
}


static int __net_init nft_gen_flow_net_init(struct net *net)
{
    struct nf_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);

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

        nft_gen_flow_offload_destroy(net, &test_zone, &test_tuple);
    }
#endif
    return 0;
}

static void __net_exit nft_gen_flow_net_exit(struct net *net)
{
    struct nf_gen_flow_offload_net *gnet = nft_gen_flow_offload_pernet(net);
    struct nf_gen_flow_offload_table * flowtable = rcu_access_pointer(gnet->flowtable);

    if (flowtable != NULL) {
        rcu_assign_pointer(gnet->flowtable, NULL);

        synchronize_rcu();

        nf_gen_flow_offload_table_free(flowtable);

        kfree(flowtable);
    }
}


static struct pernet_operations nft_gen_flow_offload_net_ops = {
    .init           = nft_gen_flow_net_init,
    .exit           = nft_gen_flow_net_exit, // TODO: change to batch
    .id             = &nft_gen_flow_offload_net_id,
    .size           = sizeof(struct nf_gen_flow_offload_net),
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
