/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/*
 * Copyright (c) 2018 Mellanox Technologies. All rights reserved.
 */

#ifndef _MLX5_ESWITCH_
#define _MLX5_ESWITCH_

#include <linux/mlx5/driver.h>

#define MLX5_ESWITCH_MANAGER(mdev) MLX5_CAP_GEN(mdev, eswitch_manager)

enum {
	SRIOV_NONE,
	SRIOV_LEGACY,
	SRIOV_OFFLOADS
};

enum {
	REP_ETH,
	REP_IB,
	NUM_REP_TYPES,
};

enum {
	REP_UNREGISTERED,
	REP_REGISTERED,
	REP_ENABLED,
	REP_LOADED,
};

static inline const char *mlx5_rep_state_str(int state)
{
	switch (state) {
	case REP_UNREGISTERED: return "REP_UNREGISTERED";
	case REP_REGISTERED: return "REP_REGISTERED";
	case REP_ENABLED: return "REP_ENABLED";
	case REP_LOADED: return "REP_LOADED";
	}
	return "Invalid rep state";
}

static inline const char *mlx5_rep_type_str(int type)
{
	switch (type) {
	case REP_ETH: return "ETH";
	case REP_IB: return "IB";
	}
	return "Invalid rep type";
}

struct mlx5_eswitch_rep;
struct mlx5_eswitch_rep_if {
	int		       (*load)(struct mlx5_core_dev *dev,
				       struct mlx5_eswitch_rep *rep);
	void		       (*unload)(struct mlx5_eswitch_rep *rep);
	void		       *(*get_proto_dev)(struct mlx5_eswitch_rep *rep);
	void			*priv;
	u8		       state;
};

struct mlx5_eswitch_rep {
	struct mlx5_eswitch_rep_if rep_if[NUM_REP_TYPES];
	u16		       vport;
	u8		       hw_id[ETH_ALEN];
	u16		       vlan;
	u32		       vlan_refcount;
};

void mlx5_eswitch_register_vport_rep(struct mlx5_eswitch *esw,
				     int vport_index,
				     struct mlx5_eswitch_rep_if *rep_if,
				     u8 rep_type);
void mlx5_eswitch_unregister_vport_rep(struct mlx5_eswitch *esw,
				       int vport_index,
				       u8 rep_type);
void *mlx5_eswitch_get_proto_dev(struct mlx5_eswitch *esw,
				 int vport,
				 u8 rep_type);
struct mlx5_eswitch_rep *mlx5_eswitch_vport_rep(struct mlx5_eswitch *esw,
						int vport);
void *mlx5_eswitch_uplink_get_proto_dev(struct mlx5_eswitch *esw, u8 rep_type);
u8 mlx5_eswitch_mode(struct mlx5_eswitch *esw);
struct mlx5_flow_handle *
mlx5_eswitch_add_send_to_vport_rule(struct mlx5_eswitch *esw,
				    int vport, u32 sqn);

static inline int mlx5_uplink_rep_idx(struct mlx5_core_dev *dev)
{
	return MLX5_TOTAL_REPS(dev) - 1;
}

#endif
