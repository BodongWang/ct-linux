/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_CT_H
#define __NET_TC_CT_H

#include <net/act_api.h>

struct tcf_conntrack_info {
	struct tc_action common;
	struct net *net;
	u16 zone;
};

#define to_conntrack(a) ((struct tcf_conntrack_info *)a)

#endif /* __NET_TC_CT_H */
