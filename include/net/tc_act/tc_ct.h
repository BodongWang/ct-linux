/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_CT_H
#define __NET_TC_CT_H

#include <net/act_api.h>
#include <uapi/linux/tc_act/tc_ct.h>

struct tcf_conntrack_info {
	struct tc_action common;
	struct net *net;
	u16 zone;
};

#define to_conntrack(a) ((struct tcf_conntrack_info *)a)

static inline bool is_tcf_ct(const struct tc_action *a)
{
#ifdef CONFIG_NET_CLS_ACT
	if (a->ops && a->ops->type == TCA_ACT_CONNTRACK)
		return true;
#endif
	return false;
}

#endif /* __NET_TC_CT_H */
