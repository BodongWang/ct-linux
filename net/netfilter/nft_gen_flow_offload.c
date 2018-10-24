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
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/rhashtable.h>
#include <net/ip.h> /* for ipv4 options. */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

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



static struct nf_gen_flow_offload_table __rcu *_flowtable;

static atomic_t offloaded_flow_cnt;

static unsigned int offloaded_ct_timeout = 30*HZ;

module_param(offloaded_ct_timeout, uint, 0644);


#define PORTING_FLOW_TABLE

#ifdef PORTING_FLOW_TABLE

struct flow_table_stat {
    struct spinlock lock;
    u32 added;
    u32 add_failed;
    u32 add_racing;
    u32 aged;
};




struct nf_gen_flow_offload_table {
    struct list_head         list;
    struct rhashtable        rhashtable;
    struct delayed_work      gc_work;
    struct flow_table_stat   stats; 
};

enum nf_gen_flow_offload_tuple_dir {
    FLOW_OFFLOAD_DIR_ORIGINAL = IP_CT_DIR_ORIGINAL,
    FLOW_OFFLOAD_DIR_REPLY    = IP_CT_DIR_REPLY,
    FLOW_OFFLOAD_DIR_MAX      = IP_CT_DIR_MAX
};


struct nf_gen_flow_offload_tuple_rhash {
    struct rhash_head           node;
    struct nf_conntrack_tuple   tuple;
    struct nf_conntrack_zone    zone; // TODO: FIXME, less memory footprint
};



#define FLOW_OFFLOAD_DYING      0x1
#define FLOW_OFFLOAD_TEARDOWN   0x2
#define FLOW_OFFLOAD_AGING      0x4
#define FLOW_OFFLOAD_EXPIRED    0x8

struct nf_gen_flow_offload {
    struct nf_gen_flow_offload_tuple_rhash        tuplehash[FLOW_OFFLOAD_DIR_MAX];
    u32    flags;
    u64    timeout;
};


struct nf_gen_flow_offload_entry {
    struct nf_gen_flow_offload     flow;
    struct nf_conn          *ct;
    struct rcu_head         rcu_head;
    struct spinlock         dep_lock; // FIXME, narrow down spin_lock, don't call user callback with locked.
    struct list_head        deps;
    struct work_struct      work;
    struct nf_gen_flow_ct_stat stats;
};

static inline void tstat_added_inc(struct nf_gen_flow_offload_table *tbl)
{
    spin_lock(&tbl->stats.lock);
	tbl->stats.added++;
    spin_unlock(&tbl->stats.lock);
}

static inline u32 tstat_added_get(struct nf_gen_flow_offload_table *tbl)
{
	return tbl->stats.added;
}

static inline void tstat_add_failed_inc(struct nf_gen_flow_offload_table *tbl)
{
    spin_lock(&tbl->stats.lock);
	tbl->stats.add_failed++;
    spin_unlock(&tbl->stats.lock);
}

static inline u32 tstat_add_failed_get(struct nf_gen_flow_offload_table *tbl)
{
	return tbl->stats.add_failed;
}

static inline void tstat_add_racing_inc(struct nf_gen_flow_offload_table *tbl)
{
    spin_lock(&tbl->stats.lock);
	tbl->stats.add_racing++;
    spin_unlock(&tbl->stats.lock);
}

static inline u32 tstat_add_racing_get(struct nf_gen_flow_offload_table *tbl)
{
	return tbl->stats.add_racing;
}

static inline void tstat_aged_inc(struct nf_gen_flow_offload_table *tbl)
{
    spin_lock(&tbl->stats.lock);
	tbl->stats.aged++;
    spin_unlock(&tbl->stats.lock);
}

static inline u32 tstat_aged_get(struct nf_gen_flow_offload_table *tbl)
{
	return tbl->stats.aged;
}



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
        return ERR_PTR(-EINVAL);

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

    return ERR_PTR(-ENOMEM);
}


static void nf_gen_flow_offload_fixup_ct_state(struct nf_conn *ct)
{
    const struct nf_conntrack_l4proto *l4proto;
    struct net *net = nf_ct_net(ct);
    unsigned int *timeouts;
    unsigned int timeout;
    int l4num;

    l4num = nf_ct_protonum(ct);
    l4proto = __nf_ct_l4proto_find(nf_ct_l3num(ct), l4num);
    if (!l4proto)
        return;

    timeouts = l4proto->get_timeouts(net);
    if (!timeouts)
        return;

    /* FIXME, This is not safe way, since tcp state may be changed during this update */
    if (l4num == IPPROTO_TCP) {
        timeout = timeouts[ct->proto.tcp.state];
    }
    else if (l4num == IPPROTO_UDP)
        timeout = timeouts[UDP_CT_REPLIED];
    else
        return;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,0)
    {
        unsigned long newtime = jiffies + timeout;

        /* Only update the timeout if the new timeout is at least
           HZ jiffies from the old timeout. Need del_timer for race
           avoidance (may already be dying). */
        if (newtime - ct->timeout.expires >= HZ)
            mod_timer_pending(&ct->timeout, newtime);
    }
#else
    ct->timeout = (u32)jiffies + timeout;
#endif
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
    .head_offset            = offsetof(struct nf_gen_flow_offload_tuple_rhash, node),
    .hashfn                 = _flow_offload_hash,
    .obj_hashfn             = _flow_offload_hash_obj,
    .obj_cmpfn              = _flow_offload_hash_cmp,
    .automatic_shrinking    = true,
};

static int nf_gen_flow_offload_add(struct nf_gen_flow_offload_table *flow_table,
                                                struct nf_gen_flow_offload *flow)
{
    int ret;
    ret = rhashtable_insert_fast(&flow_table->rhashtable,
                   &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].node,
                   nf_gen_flow_offload_rhash_params);
    if (ret)
        return ret;
        
    ret = rhashtable_insert_fast(&flow_table->rhashtable,
               &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].node,
               nf_gen_flow_offload_rhash_params);

    return ret;
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

    atomic_dec(&offloaded_flow_cnt);

    /* fix ct_state after OFFLOAD is cleared due to gc_worker may update
       timeout with OFFLOAD_BIT set */
    nf_gen_flow_offload_fixup_ct_state(e->ct);

    nft_gen_flow_offload_destroy_dep(flow);
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
                tstat_aged_inc(flow_table);
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

    spin_lock_init(&flowtable->stats.lock);

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

static struct flow_offload_dep_ops __rcu *flow_dep_ops = NULL;

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
    struct nf_gen_flow_offload_table *flowtable;
    struct nf_gen_flow_offload *flow;
    int ret;

    flow = nf_gen_flow_offload_alloc(ct, zone_id, 0);
    if (IS_ERR(flow)) {
        ret = PTR_ERR(flow);
        goto err_flow_alloc;
    }
    
    rcu_read_lock();
    flowtable = rcu_dereference(_flowtable);
    if (flowtable) {
        ret = nf_gen_flow_offload_add(flowtable, flow);
        if (ret < 0)
            goto err_flow_add;

        if (ret_flow)
            *ret_flow = flow;

        rcu_read_unlock();

        atomic_inc(&offloaded_flow_cnt);

        return ret;
    }

err_flow_add:
    rcu_read_unlock();
    nf_gen_flow_offload_free(flow);
err_flow_alloc:
    clear_bit(IPS_OFFLOAD_BIT, &ct->status);

    return ret;
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
    struct nf_gen_flow_offload_table *flowtable;
    struct nf_gen_flow_offload_tuple_rhash *tuplehash = NULL;

    rcu_read_lock();

    flowtable = rcu_dereference(_flowtable);
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
    struct flow_offload_dep_ops * ops;

    e = container_of(flow, struct nf_gen_flow_offload_entry, flow);

    rcu_read_lock();
    ops = rcu_dereference(flow_dep_ops);
    if (ops && ops->get_stats) {
        /* retrieve stats by callbacks */
        spin_lock(&e->dep_lock);
        last_used = e->stats.last_used;
        ops->get_stats(&e->stats, &e->deps);
        spin_unlock(&e->dep_lock);

        /* update timeout with new last_used value, last_used is set as jiffies in drv;
           When TCP is disconnected by FIN, conntrack conneciton may be held by IPS_OFFLOAD
           until it is unset */

        if ((last_used == 0) || (e->stats.last_used > last_used))
            flow->timeout = e->stats.last_used + offloaded_ct_timeout;
    }
    rcu_read_unlock();

    return 0;
}

/* connection is aged out, notify all dependencies  */
static void _flow_offload_destroy_dep_async(struct work_struct *work)
{
    struct nf_gen_flow_offload_entry *e;
    struct flow_offload_dep_ops * ops;

    e = container_of(work, struct nf_gen_flow_offload_entry, work);

    pr_debug("async destroy for ct %p", &e->flow);

    rcu_read_lock();
    ops = rcu_dereference(flow_dep_ops);
    if (ops && ops->destroy) {
        spin_lock(&e->dep_lock);
        ops->destroy(&e->deps);
        spin_unlock(&e->dep_lock);
    }
    rcu_read_unlock();

    nf_gen_flow_offload_free(&e->flow);
}

static int nft_gen_flow_offload_destroy_dep(struct nf_gen_flow_offload *flow)
{
    struct nf_gen_flow_offload_entry *e;
    bool async_needed = false;

    e = container_of(flow, struct nf_gen_flow_offload_entry, flow);

    if (rcu_access_pointer(flow_dep_ops)) {
        spin_lock(&e->dep_lock);
        if (!list_empty_careful(&e->deps)) {
            async_needed = true;
        }
        spin_unlock(&e->dep_lock);
    }

    if (async_needed) {
        INIT_WORK(&e->work, _flow_offload_destroy_dep_async);
        schedule_work(&e->work);
    } else
        nf_gen_flow_offload_free(&e->flow);

    return 0;
}


/* EXPORT FUNCTIONS */

void nft_gen_flow_offload_dep_ops_register(struct flow_offload_dep_ops * ops)
{
    rcu_assign_pointer(flow_dep_ops, ops);
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_dep_ops_register);


void nft_gen_flow_offload_dep_ops_unregister(struct flow_offload_dep_ops * ops)
{
    struct nf_gen_flow_offload_table *flowtable;

    rcu_assign_pointer(flow_dep_ops, NULL);

    rcu_read_lock();
    flowtable = rcu_dereference(_flowtable);

    /* cleanup all connections, for dep list member, drv assures no need to free explicitly */
    nf_gen_flow_offload_table_iterate(flowtable, nf_gen_flow_offload_table_do_cleanup, NULL);
    rcu_read_unlock();
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_dep_ops_unregister);



int nft_gen_flow_offload_add(const struct net *net,
            const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple *tuple, void *dep)
{
    const struct nf_conntrack_tuple_hash *thash;
    struct nf_gen_flow_offload_tuple_rhash *fhash;
    enum nf_gen_flow_offload_tuple_dir dir;
    struct nf_gen_flow_offload *flow;
    struct nf_gen_flow_offload_entry *entry;
    struct nf_conn *ct;
    int ret = 0;
    struct flow_offload_dep_ops * ops;
    struct nf_gen_flow_offload_table *flowtable;

    if (rcu_access_pointer(flow_dep_ops) == NULL)
        return -EPERM;

    if (rcu_access_pointer(_flowtable) == NULL)
        return -ENOENT;

    _flow_offload_debug_op(zone, tuple, "Add");

    /* lookup */
    fhash = _flowtable_lookup(net, zone, tuple);
    if (fhash) {
        dir = fhash->tuple.dst.dir;
        entry = container_of(fhash, struct nf_gen_flow_offload_entry, flow.tuplehash[dir]);
    } else {
        thash = nf_conntrack_find_get((struct net *)net, zone, tuple);
        if (!thash) {
            ret = -EINVAL;
            goto _flow_add_exit;
        }
        
        ct = nf_ct_tuplehash_to_ctrack(thash);

        ret = _check_ct_status(ct);
        if (ret ==  0) {
            ret = _flowtable_add_entry(net, zone->id, ct, &flow);
        } else if (ret == -EEXIST) {
            /* cocurrency, tell user to try again */
            ret = -EAGAIN;
        }

        nf_ct_put(ct);
        if (ret < 0) goto _flow_add_exit;

        entry = container_of(flow, struct nf_gen_flow_offload_entry, flow);
    }


    rcu_read_lock();
    ops = rcu_dereference(flow_dep_ops);
    if (ops && ops->add) {
        spin_lock(&entry->dep_lock);

        /* checking if it was destroyed before we got spin lock*/
        if (entry->flow.flags & (FLOW_OFFLOAD_TEARDOWN |
                                    FLOW_OFFLOAD_DYING)) {
            spin_unlock(&entry->dep_lock);
            rcu_read_unlock();
            ret = -EAGAIN;
            goto _flow_add_exit;
        }

        ret = ops->add(dep, &entry->deps);
        if (ret && (list_empty_careful(&entry->deps))) {
            entry->flow.flags |= FLOW_OFFLOAD_TEARDOWN;

            spin_unlock(&entry->dep_lock);
            rcu_read_unlock();
            goto _flow_add_exit;
        }

        spin_unlock(&entry->dep_lock);

        if (ops->get_stats) {
            /* update timeout for new dep*/
            entry->flow.timeout = jiffies + offloaded_ct_timeout;

            nf_gen_flow_offload_set_aging(&entry->flow);
        }
    } else {
        entry->flow.flags |= FLOW_OFFLOAD_TEARDOWN;
    }
    
    rcu_read_unlock();
    
_flow_add_exit:  
    rcu_read_lock();
    flowtable = rcu_dereference(_flowtable);
    if (flowtable) {
        tstat_added_inc(flowtable);
        if (ret < 0)
            tstat_add_failed_inc(flowtable);
        if (ret == -EAGAIN)
            tstat_add_racing_inc(flowtable);
    }
    rcu_read_unlock();

    return ret;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_add);

int nft_gen_flow_offload_remove(const struct net *net,
            const struct nf_conntrack_zone *zone,
            const struct nf_conntrack_tuple * tuple, void *dep)
{
    struct nf_gen_flow_offload_tuple_rhash *fhash;
    enum nf_gen_flow_offload_tuple_dir dir;
    struct nf_gen_flow_offload_entry *entry;
    int ret;
    struct flow_offload_dep_ops * ops;

    NFT_GEN_FLOW_FUNC_ENTRY();

    if (rcu_access_pointer(flow_dep_ops) == NULL)
        return -EPERM;

    if (rcu_access_pointer(_flowtable) == NULL)
        return -ENOENT;

    _flow_offload_debug_op(zone, tuple, "Rmv");

    /* lookup */
    fhash = _flowtable_lookup(net, zone, tuple);
    if (fhash) {
        dir = fhash->tuple.dst.dir;
        entry = container_of(fhash, struct nf_gen_flow_offload_entry, flow.tuplehash[dir]);

        rcu_read_lock();
        ops = rcu_dereference(flow_dep_ops);
        if (ops && ops->remove) {
            /* try to remove it anyway, RCU holds this entry
                and spin can help with list operation */
            spin_lock(&entry->dep_lock);
            ops->remove(dep, &entry->deps);
            spin_unlock(&entry->dep_lock);
        }
        rcu_read_unlock();

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
    struct nf_gen_flow_offload_tuple_rhash *thash;
    struct nf_gen_flow_offload *flow;
    enum nf_gen_flow_offload_tuple_dir dir;

    NFT_GEN_FLOW_FUNC_ENTRY();

    if (rcu_access_pointer(_flowtable) == NULL)
        return 0;

    _flow_offload_debug_op(zone, tuple, "Destroy");

    thash = _flowtable_lookup(net, zone, tuple);
    if (thash != NULL) {
        dir = thash->tuple.dst.dir;

        flow = container_of(thash, struct nf_gen_flow_offload, tuplehash[dir]);

        flow->flags |= FLOW_OFFLOAD_TEARDOWN; // FIXME: replace flag set by set_and_test to start async work
    }

    NFT_GEN_FLOW_FUNC_EXIT();

    return 0;
}

EXPORT_SYMBOL_GPL(nft_gen_flow_offload_destroy);


static int
nft_gen_flow_offload_init(const struct net *net)
{
    struct nf_gen_flow_offload_table *flowtable;

    NFT_GEN_FLOW_FUNC_ENTRY();

    flowtable = kzalloc(sizeof(*flowtable), GFP_KERNEL);

    nf_gen_flow_offload_table_init(flowtable);

    rcu_assign_pointer(_flowtable, flowtable);

    NFT_GEN_FLOW_FUNC_EXIT();

    return 0;
}

#define SANITY_TEST
#ifdef SANITY_TEST

static unsigned int sanity_src_ip = 0xc0a86e01;
module_param(sanity_src_ip, uint, 0644);

static unsigned int sanity_dst_ip = 0xc0a86e8B;
module_param(sanity_dst_ip, uint, 0644);

static unsigned int sanity_l3prot = NFPROTO_IPV4;
module_param(sanity_l3prot, uint, 0644);

static unsigned int sanity_l4prot = 16;
module_param(sanity_l4prot, uint, 0644);


static unsigned int sanity_src_port = 1000;
module_param(sanity_src_port, uint, 0644);

static unsigned int sanity_dst_port = 22;
module_param(sanity_dst_port, uint, 0644);


enum {
    OFFLOADED_DEBUG_EN_SANITY_BIT,
    OFFLOADED_DEBUG_EN_SANITY = (1 << OFFLOADED_DEBUG_EN_SANITY_BIT),

    OFFLOADED_DEBUG_EN_SANITY_STATS_BIT,
    OFFLOADED_DEBUG_EN_SANITY_STATS = (1 << OFFLOADED_DEBUG_EN_SANITY_STATS_BIT),

};


static unsigned int sanity_flags = 0;
module_param(sanity_flags, uint, 0644);

static int _dummy_dep_add(void * ptr, struct list_head *head)
{
    pr_debug("_dummy_dep_add %p", ptr);

    return 0;
}

static void _dummy_dep_del(void * ptr, struct list_head *head)
{
    pr_debug("_dummy_dep_del %p", ptr);
}

static int _dummy_dep_destroy(struct list_head *head)
{
    pr_debug("_dummy_dep_destroy");

    return 0;
}

static void _dummy_get_stat(struct nf_gen_flow_ct_stat *stats, struct list_head *head)
{
    pr_debug("_dummy_get_stat");
    if (sanity_flags & OFFLOADED_DEBUG_EN_SANITY_STATS)
        stats->last_used = jiffies;
}


static struct flow_offload_dep_ops dummy_ops = {
    .add        = _dummy_dep_add,
    .remove     = _dummy_dep_del,
    .destroy    = _dummy_dep_destroy,
    .get_stats  = _dummy_get_stat
};


#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)

/* proc_create_single_data can't work in 3.10,
   need full seq operations to support single data show,
   implement it soon */
int __init nft_gen_flow_offload_proc_init(void)
{
    return 0;
}

void __exit nft_gen_flow_offload_proc_exit(void)
{
    return;
}

#else

static int nf_conntrack_offloaded_proc_show(struct seq_file *m, void *v)
{
    int flow_cnt;
    struct nf_gen_flow_offload_table * flowtable;
    
    flow_cnt = atomic_read(&offloaded_flow_cnt);

    seq_printf(m, "total %d flows offloaded \n",
                    flow_cnt);

    rcu_read_lock();
    flowtable = rcu_dereference(_flowtable);
    if (flowtable) {
        seq_printf(m, "tstats add: success %d failed %d racing %d\n",
                        tstat_added_get(flowtable),
                        tstat_add_failed_get(flowtable),
                        tstat_add_racing_get(flowtable));

        seq_printf(m, "tstats gc: aged %d \n",
                        tstat_aged_get(flowtable));
    }
    rcu_read_unlock();

    return 0;
}

int __init nft_gen_flow_offload_proc_init(void)
{
    struct proc_dir_entry *p;
    int rc = -ENOMEM;

    p = proc_create_single_data("nf_conntrack_offloaded", 0444, init_net.proc_net,
                                nf_conntrack_offloaded_proc_show, NULL);
    if (!p) {
        pr_debug("can't make nf_conntrack_offloaded proc_entry");
        return rc;
    }

    return 0;
}

void __exit nft_gen_flow_offload_proc_exit(void)
{
    remove_proc_entry("nf_conntrack_offloaded", init_net.proc_net);
}

#endif

static int __init nft_gen_flow_offload_module_init(void)
{
    atomic_set(&offloaded_flow_cnt, 0);

    rcu_assign_pointer(_flowtable, NULL);

    nft_gen_flow_offload_init(&init_net);

#ifdef SANITY_TEST
    if (sanity_flags & OFFLOADED_DEBUG_EN_SANITY) {
        struct nf_conntrack_tuple test_tuple;
        struct nf_conntrack_zone test_zone = {NF_CT_DEFAULT_ZONE_ID, 0, NF_CT_DEFAULT_ZONE_DIR};

        nft_gen_flow_offload_dep_ops_register(&dummy_ops);

        memset(&test_tuple, 0, sizeof(test_tuple));

        test_tuple.src.u3.ip = htonl(sanity_src_ip);
        test_tuple.src.u.tcp.port = htons(sanity_src_port);
        test_tuple.src.l3num = sanity_l3prot;

        test_tuple.dst.u3.ip = htonl(sanity_dst_ip);
        test_tuple.dst.u.tcp.port = htons(sanity_dst_port);
        test_tuple.dst.protonum = sanity_l4prot;
        test_tuple.dst.dir = NF_CT_ZONE_DIR_ORIG;

        nft_gen_flow_offload_add(&init_net, &test_zone, &test_tuple, (void*)0xdeadbeef);

        //nft_gen_flow_offload_destroy(net, &test_zone, &test_tuple);
    }
#endif

    nft_gen_flow_offload_proc_init();

    return 0;
}



static void __exit nft_gen_flow_offload_module_exit(void)
{
    struct nf_gen_flow_offload_table * flowtable;

    nft_gen_flow_offload_proc_exit();

#ifdef SANITY_TEST
    if (sanity_flags & OFFLOADED_DEBUG_EN_SANITY) {
        nft_gen_flow_offload_dep_ops_unregister(&dummy_ops);
    }
#endif

    flowtable = rcu_dereference(_flowtable);
    if (flowtable != NULL) {
        rcu_assign_pointer(_flowtable, NULL);

        synchronize_rcu();

        nf_gen_flow_offload_table_free(flowtable);

        kfree(flowtable);
    }
}

module_init(nft_gen_flow_offload_module_init);
module_exit(nft_gen_flow_offload_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lidong Jiang <jianglidong3@jd.com>");
