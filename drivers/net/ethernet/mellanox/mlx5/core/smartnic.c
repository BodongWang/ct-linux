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

#include <linux/module.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/eswitch.h>
#include "mlx5_core.h"

int mlx5_query_host_params_num_vfs(struct mlx5_core_dev *dev, int *num_vf)
{
	int outlen = MLX5_ST_SZ_BYTES(query_host_params_out);
	u32 in[MLX5_ST_SZ_DW(query_host_params_in)] = {0};
	void *out;
	void *ctx;
	int err;

	out = kvzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(query_host_params_in, in, opcode, MLX5_CMD_OP_QUERY_HOST_PARAMS);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out, outlen);
	if (err) {
		mlx5_core_warn(dev, "err = %d\n", err);
		goto error1;
	}

	ctx = MLX5_ADDR_OF(query_host_params_out, out, host_params_context);
	mlx5_core_dbg(dev, "host_number %d\n", MLX5_GET(host_params_context, ctx, host_number));
	mlx5_core_dbg(dev, "host_num_of_vfs %d\n", MLX5_GET(host_params_context, ctx, host_num_of_vfs));
	mlx5_core_dbg(dev, "host_pci_bus 0x%x\n", MLX5_GET(host_params_context, ctx, host_pci_bus));
	mlx5_core_dbg(dev, "host_pci_device 0x%x\n", MLX5_GET(host_params_context, ctx, host_pci_device));
	mlx5_core_dbg(dev, "host_pci_function %d\n", MLX5_GET(host_params_context, ctx, host_pci_function));
	*num_vf = MLX5_GET(host_params_context, ctx, host_num_of_vfs);

error1:
	kvfree(out);
	return err;
}

static void host_params_handler(struct work_struct *work)
{
	struct mlx5_ec_work *ecw = container_of(work, struct mlx5_ec_work, work);
	struct mlx5_core_dev *dev = ecw->dev;
	int num_vf;
	int err;

	if (!mlx5_core_is_ecpf(dev)) {
		mlx5_core_warn(dev, "invalid ec params event - ignoring\n");
		return;
	}

	if (!MLX5_ESWITCH_MANAGER(dev))
		return;

	err = mlx5_query_host_params_num_vfs(dev, &num_vf);
	if (err)
		mlx5_core_warn(dev, "mlx5_query_host_params_num_vfs failed\n");

	kfree(ecw);
}

void mlx5_host_params_update(struct mlx5_core_dev *dev)
{
	struct mlx5_ec_work *ecw;

	ecw = kzalloc(sizeof(*ecw), GFP_ATOMIC);
	if (!ecw)
		return;

	ecw->dev = dev;
	INIT_WORK(&ecw->work, host_params_handler);
	queue_work(dev->priv.wq, &ecw->work);
}

int mlx5_ec_init(struct mlx5_core_dev *dev)
{
	struct mlx5_priv *priv = &dev->priv;

	priv->wq = create_singlethread_workqueue("mlx5_generic");
	if (!priv->wq)
		return -ENOMEM;

	return 0;
}

void mlx5_ec_cleanup(struct mlx5_core_dev *dev)
{
	struct mlx5_priv *priv = &dev->priv;

	destroy_workqueue(priv->wq);
}
