// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2018 Mellanox Technologies */

#include <linux/mlx5/vport.h>
#include "lib/devcom.h"
#include "mlx5_core.h"

static LIST_HEAD(devcom_list);

#define devcom_for_each_component(priv, comp, iter) \
	for (iter = 0; \
	     comp = &(priv)->components[iter], iter < MLX5_DEVCOM_NUM_COMPONENTS; \
	     iter++)

struct mlx5_devcom_component {
	struct {
		void __rcu *data;
	} device[MLX5_DEVCOM_PORTS_SUPPORTED];

	mlx5_devcom_event_handler_t handler;
	struct rw_semaphore sem;
	bool paired;
};

struct mlx5_devcom_list {
	struct list_head list;

	struct mlx5_devcom_component components[MLX5_DEVCOM_NUM_COMPONENTS];
	struct mlx5_core_dev *devs[MLX5_DEVCOM_PORTS_SUPPORTED];
};

struct mlx5_devcom {
	struct mlx5_devcom_list *priv;
	int idx;
};

static struct mlx5_devcom_list *mlx5_devcom_list_alloc(void)
{
	struct mlx5_devcom_component *comp;
	struct mlx5_devcom_list *priv;
	int i;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	devcom_for_each_component(priv, comp, i)
		init_rwsem(&comp->sem);

	return priv;
}

static struct mlx5_devcom *mlx5_devcom_alloc(struct mlx5_devcom_list *priv,
					     u8 idx)
{
	struct mlx5_devcom *devcom;

	devcom = kzalloc(sizeof(*devcom), GFP_KERNEL);
	if (!devcom)
		return NULL;

	devcom->priv = priv;
	devcom->idx = idx;
	return devcom;
}

/* Must be called with intf_mutex held */
//在系统中注册一个 可以支持多端口设备通信的 devcom 实例（struct mlx5_devcom），用于后续设备间组件（如 IPsec、TLS 等）的通信协作。
struct mlx5_devcom *mlx5_devcom_register_device(struct mlx5_core_dev *dev)
{
	struct mlx5_devcom_list *priv = NULL, *iter;
	struct mlx5_devcom *devcom = NULL;
	bool new_priv = false;
	u64 sguid0, sguid1;
	int idx, i;

	if (!mlx5_core_is_pf(dev))
		return NULL;
	if (MLX5_CAP_GEN(dev, num_lag_ports) != MLX5_DEVCOM_PORTS_SUPPORTED)//固件支持
		return NULL;

	mlx5_dev_list_lock();
	sguid0 = mlx5_query_nic_system_image_guid(dev);//获取设备的 System Image GUID
	list_for_each_entry(iter, &devcom_list, list) {//遍历已注册的 devcom 共享域列表 devcom_list，查找是否已经有与当前设备属于同一物理设备
		struct mlx5_core_dev *tmp_dev = NULL;

		idx = -1;
		for (i = 0; i < MLX5_DEVCOM_PORTS_SUPPORTED; i++) {
			if (iter->devs[i])
				tmp_dev = iter->devs[i];
			else
				idx = i;
		}

		if (idx == -1)
			continue;

		sguid1 = mlx5_query_nic_system_image_guid(tmp_dev);
		if (sguid0 != sguid1)
			continue;

		priv = iter;
		break;
	}

	if (!priv) {
		priv = mlx5_devcom_list_alloc();//为当前设备新建一个 devcom 通信域
		if (!priv) {
			devcom = ERR_PTR(-ENOMEM);
			goto out;
		}

		idx = 0;
		new_priv = true;
	}

	priv->devs[idx] = dev;
	devcom = mlx5_devcom_alloc(priv, idx);//为当前设备创建 struct mlx5_devcom 实例
	if (!devcom) {
		if (new_priv)
			kfree(priv);
		devcom = ERR_PTR(-ENOMEM);
		goto out;
	}

	if (new_priv)
		list_add(&priv->list, &devcom_list);
out:
	mlx5_dev_list_unlock();
	return devcom;
}

/* Must be called with intf_mutex held */
void mlx5_devcom_unregister_device(struct mlx5_devcom *devcom)
{
	struct mlx5_devcom_list *priv;
	int i;

	if (IS_ERR_OR_NULL(devcom))
		return;

	mlx5_dev_list_lock();
	priv = devcom->priv;
	priv->devs[devcom->idx] = NULL;

	kfree(devcom);

	for (i = 0; i < MLX5_DEVCOM_PORTS_SUPPORTED; i++)
		if (priv->devs[i])
			break;

	if (i != MLX5_DEVCOM_PORTS_SUPPORTED)
		goto out;

	list_del(&priv->list);
	kfree(priv);
out:
	mlx5_dev_list_unlock();
}

void mlx5_devcom_register_component(struct mlx5_devcom *devcom,
				    enum mlx5_devcom_components id,
				    mlx5_devcom_event_handler_t handler,
				    void *data)
{
	struct mlx5_devcom_component *comp;

	if (IS_ERR_OR_NULL(devcom))
		return;

	WARN_ON(!data);

	comp = &devcom->priv->components[id];
	down_write(&comp->sem);
	comp->handler = handler;
	rcu_assign_pointer(comp->device[devcom->idx].data, data);
	up_write(&comp->sem);
}

void mlx5_devcom_unregister_component(struct mlx5_devcom *devcom,
				      enum mlx5_devcom_components id)
{
	struct mlx5_devcom_component *comp;

	if (IS_ERR_OR_NULL(devcom))
		return;

	comp = &devcom->priv->components[id];
	down_write(&comp->sem);
	RCU_INIT_POINTER(comp->device[devcom->idx].data, NULL);
	up_write(&comp->sem);
	synchronize_rcu();
}

int mlx5_devcom_send_event(struct mlx5_devcom *devcom,
			   enum mlx5_devcom_components id,
			   int event,
			   void *event_data)
{
	struct mlx5_devcom_component *comp;
	int err = -ENODEV, i;

	if (IS_ERR_OR_NULL(devcom))
		return err;

	comp = &devcom->priv->components[id];
	down_write(&comp->sem);
	for (i = 0; i < MLX5_DEVCOM_PORTS_SUPPORTED; i++) {
		void *data = rcu_dereference_protected(comp->device[i].data,
						       lockdep_is_held(&comp->sem));

		if (i != devcom->idx && data) {
			err = comp->handler(event, data, event_data);
			break;
		}
	}

	up_write(&comp->sem);
	return err;
}

void mlx5_devcom_set_paired(struct mlx5_devcom *devcom,
			    enum mlx5_devcom_components id,
			    bool paired)
{
	struct mlx5_devcom_component *comp;

	comp = &devcom->priv->components[id];
	WARN_ON(!rwsem_is_locked(&comp->sem));

	WRITE_ONCE(comp->paired, paired);
}

bool mlx5_devcom_is_paired(struct mlx5_devcom *devcom,
			   enum mlx5_devcom_components id)
{
	if (IS_ERR_OR_NULL(devcom))
		return false;

	return READ_ONCE(devcom->priv->components[id].paired);
}

void *mlx5_devcom_get_peer_data(struct mlx5_devcom *devcom,
				enum mlx5_devcom_components id)
{
	struct mlx5_devcom_component *comp;
	int i;

	if (IS_ERR_OR_NULL(devcom))
		return NULL;

	comp = &devcom->priv->components[id];
	down_read(&comp->sem);
	if (!READ_ONCE(comp->paired)) {
		up_read(&comp->sem);
		return NULL;
	}

	for (i = 0; i < MLX5_DEVCOM_PORTS_SUPPORTED; i++)
		if (i != devcom->idx)
			break;

	return rcu_dereference_protected(comp->device[i].data, lockdep_is_held(&comp->sem));
}

void *mlx5_devcom_get_peer_data_rcu(struct mlx5_devcom *devcom, enum mlx5_devcom_components id)
{
	struct mlx5_devcom_component *comp;
	int i;

	if (IS_ERR_OR_NULL(devcom))
		return NULL;

	for (i = 0; i < MLX5_DEVCOM_PORTS_SUPPORTED; i++)
		if (i != devcom->idx)
			break;

	comp = &devcom->priv->components[id];
	/* This can change concurrently, however 'data' pointer will remain
	 * valid for the duration of RCU read section.
	 */
	if (!READ_ONCE(comp->paired))
		return NULL;

	return rcu_dereference(comp->device[i].data);
}

void mlx5_devcom_release_peer_data(struct mlx5_devcom *devcom,
				   enum mlx5_devcom_components id)
{
	struct mlx5_devcom_component *comp = &devcom->priv->components[id];

	up_read(&comp->sem);
}
