/*
 * net/sched/act_conntrack.c  connection tracking action
 *
 * Copyright (c) 2018 Yossi Kuperman <yossiku@mellanox.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
*/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/act_api.h>
#include <uapi/linux/tc_act/tc_ct.h>
#include <net/tc_act/tc_ct.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>

static unsigned int conntrack_net_id;
static struct tc_action_ops act_conntrack_ops;

static int tcf_conntrack(struct sk_buff *skb, const struct tc_action *a,
			struct tcf_result *res)
{
	const struct nf_conntrack_tuple_hash *thash;
	struct nf_conntrack_tuple tuple;
	enum ip_conntrack_info ctinfo;
	struct tcf_conntrack_info *ca = to_conntrack(a);
	struct nf_conntrack_zone zone;
	struct nf_conn *c;
	struct net *net = dev_net(skb->dev);
	struct nf_conn *ct;
	int proto;
	int err;

	int nh_ofs;

	/* The conntrack module expects to be working at L3. */
	//nh_ofs = skb_network_offset(skb);
	//skb_pull_rcsum(skb, nh_ofs);

	spin_lock(&ca->tcf_lock);
	tcf_lastuse_update(&ca->tcf_tm);
	bstats_update(&ca->tcf_bstats, skb);

	/* FIXME: support IPv6? what about local generated traffic or input? */
	err = nf_conntrack_in(net, PF_INET,
			      NF_INET_PRE_ROUTING, skb);
	if (err != NF_ACCEPT) {
		printk("[yk] tcf_conntrack: nf_conntrack_in failed: %d\n", err);
		goto out;
	}

	nf_conntrack_confirm(skb);

out:
	//skb_push(skb, nh_ofs);
	//skb_postpush_rcsum(skb, skb->data, nh_ofs);

	spin_unlock(&ca->tcf_lock);
	return ca->tcf_action;
}

static const struct nla_policy conntrack_policy[TCA_CONNTRACK_MAX + 1] = {
	[TCA_CONNTRACK_PARMS] = { .len = sizeof(struct tc_conntrack) },
};

static int tcf_conntrack_init(struct net *net, struct nlattr *nla,
			     struct nlattr *est, struct tc_action **a,
			     int ovr, int bind,
			     struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, conntrack_net_id);
	struct nlattr *tb[TCA_CONNTRACK_MAX + 1];
	struct tcf_conntrack_info *ci;
	struct tc_conntrack *parm;
	int ret = 0;

	printk("[yk] tcf_conntrack_init\n");

	if (!nla)
		return -EINVAL;

	ret = nla_parse_nested(tb, TCA_CONNTRACK_MAX, nla, conntrack_policy,
			       NULL);
	if (ret < 0)
		return ret;

	if (!tb[TCA_CONNTRACK_PARMS])
		return -EINVAL;

	parm = nla_data(tb[TCA_CONNTRACK_PARMS]);

	if (!tcf_idr_check(tn, parm->index, a, bind)) {
		ret = tcf_idr_create(tn, parm->index, est, a,
				     &act_conntrack_ops, bind, false);
		if (ret)
			return ret;

		ci = to_conntrack(*a);
		ci->tcf_action = parm->action;
		ci->net = net;
		ci->zone = parm->zone;

		tcf_idr_insert(tn, *a);
		ret = ACT_P_CREATED;
	} else {
		ci = to_conntrack(*a);
		if (bind)
			return 0;
		tcf_idr_release(*a, bind);
		if (!ovr)
			return -EEXIST;
		/* replacing action and zone */
		ci->tcf_action = parm->action;
		ci->zone = parm->zone;
	}

	return ret;
}

static inline int tcf_conntrack_dump(struct sk_buff *skb, struct tc_action *a,
				    int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_conntrack_info *ci = to_conntrack(a);

	struct tc_conntrack opt = {
		.index   = ci->tcf_index,
		.refcnt  = ci->tcf_refcnt - ref,
		.bindcnt = ci->tcf_bindcnt - bind,
		.action  = ci->tcf_action,
		.zone   = ci->zone,
	};
	struct tcf_t t;

	if (nla_put(skb, TCA_CONNTRACK_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	tcf_tm_dump(&t, &ci->tcf_tm);
	if (nla_put_64bit(skb, TCA_CONNTRACK_TM, sizeof(t), &t,
			  TCA_CONNTRACK_PAD))
		goto nla_put_failure;

	return skb->len;
nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_conntrack_walker(struct net *net, struct sk_buff *skb,
			       struct netlink_callback *cb, int type,
			       const struct tc_action_ops *ops,
			       struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, conntrack_net_id);

	return tcf_generic_walker(tn, skb, cb, type, ops, extack);
}

static int tcf_conntrack_search(struct net *net, struct tc_action **a, u32 index,
			       struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, conntrack_net_id);

	return tcf_idr_search(tn, a, index);
}

static struct tc_action_ops act_conntrack_ops = {
	.kind		=	"ct",
	.type		=	TCA_ACT_CONNTRACK,
	.owner		=	THIS_MODULE,
	.act		=	tcf_conntrack,
	.dump		=	tcf_conntrack_dump,
	.init		=	tcf_conntrack_init,
	.walk		=	tcf_conntrack_walker,
	.lookup		=	tcf_conntrack_search,
	.size		=	sizeof(struct tcf_conntrack_info),
};

static __net_init int conntrack_init_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, conntrack_net_id);

	return tc_action_net_init(tn, &act_conntrack_ops);
}

static void __net_exit conntrack_exit_net(struct list_head *net_list)
{
	tc_action_net_exit(net_list, conntrack_net_id);
}

static struct pernet_operations conntrack_net_ops = {
	.init = conntrack_init_net,
	.exit_batch = conntrack_exit_net,
	.id   = &conntrack_net_id,
	.size = sizeof(struct tc_action_net),
};

static int __init conntrack_init_module(void)
{
	return tcf_register_action(&act_conntrack_ops, &conntrack_net_ops);
}

static void __exit conntrack_cleanup_module(void)
{
	tcf_unregister_action(&act_conntrack_ops, &conntrack_net_ops);
}

module_init(conntrack_init_module);
module_exit(conntrack_cleanup_module);
MODULE_AUTHOR("Yossi Kuperman <yossiku@mellanox.com>");
MODULE_DESCRIPTION("Connection tracking action");
MODULE_LICENSE("GPL");

