/*
 * Copyright (c) 2018, Mellanox Technologies, Ltd.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __MLX5_SMARTNIC_H__
#define __MLX5_SMARTNIC_H__

#include <linux/module.h>
#include <linux/mlx5/driver.h>
#include "mlx5_core.h"

int mlx5_query_host_params_num_vfs(struct mlx5_core_dev *dev, int *num_vf);
void mlx5_host_params_update(struct mlx5_core_dev *dev);
int mlx5_ec_init(struct mlx5_core_dev *dev);
void mlx5_ec_cleanup(struct mlx5_core_dev *dev);
int mlx5_enable_peer_pf(struct mlx5_core_dev *dev);
void mlx5_clean_peer_pf(struct mlx5_core_dev *dev);

#endif /* __MLX5_SMARTNIC_H__ */
