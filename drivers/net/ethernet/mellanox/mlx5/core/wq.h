/*
 * Copyright (c) 2013-2015, Mellanox Technologies, Ltd.  All rights reserved.
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

#ifndef __MLX5_WQ_H__
#define __MLX5_WQ_H__

#include <linux/mlx5/mlx5_ifc.h>
#include <linux/mlx5/cq.h>
#include <linux/mlx5/qp.h>

struct mlx5_wq_param {
	int		buf_numa_node;
	int		db_numa_node;
};

struct mlx5_wq_ctrl {
	struct mlx5_core_dev	*mdev;
	struct mlx5_frag_buf	buf;
	struct mlx5_db		db;
};

struct mlx5_wq_cyc {
	struct mlx5_frag_buf_ctrl fbc;
	__be32			*db;
	u16			sz;
	u16			wqe_ctr;
	u16			cur_sz;
};

struct mlx5_wq_qp {
	struct mlx5_wq_cyc	rq;
	struct mlx5_wq_cyc	sq;
};

struct mlx5_cqwq {
	struct mlx5_frag_buf_ctrl fbc;
	__be32			  *db;
	u32			  cc; /* consumer counter */
};

struct mlx5_wq_ll {
	struct mlx5_frag_buf_ctrl fbc;
	__be32			*db;
	__be16			*tail_next;
	u16			head;
	u16			wqe_ctr;
	u16			cur_sz;
};

int mlx5_wq_cyc_create(struct mlx5_core_dev *mdev, struct mlx5_wq_param *param,
		       void *wqc, struct mlx5_wq_cyc *wq,
		       struct mlx5_wq_ctrl *wq_ctrl);
void mlx5_wq_cyc_wqe_dump(struct mlx5_wq_cyc *wq, u16 ix, u8 nstrides);
void mlx5_wq_cyc_reset(struct mlx5_wq_cyc *wq);

int mlx5_wq_qp_create(struct mlx5_core_dev *mdev, struct mlx5_wq_param *param,
		      void *qpc, struct mlx5_wq_qp *wq,
		      struct mlx5_wq_ctrl *wq_ctrl);

int mlx5_cqwq_create(struct mlx5_core_dev *mdev, struct mlx5_wq_param *param,
		     void *cqc, struct mlx5_cqwq *wq,
		     struct mlx5_wq_ctrl *wq_ctrl);

int mlx5_wq_ll_create(struct mlx5_core_dev *mdev, struct mlx5_wq_param *param,
		      void *wqc, struct mlx5_wq_ll *wq,
		      struct mlx5_wq_ctrl *wq_ctrl);
void mlx5_wq_ll_reset(struct mlx5_wq_ll *wq);

void mlx5_wq_destroy(struct mlx5_wq_ctrl *wq_ctrl);

static inline u32 mlx5_wq_cyc_get_size(struct mlx5_wq_cyc *wq)
{
	return (u32)wq->fbc.sz_m1 + 1;
}

static inline int mlx5_wq_cyc_is_full(struct mlx5_wq_cyc *wq)
{
	return wq->cur_sz == wq->sz;
}

static inline int mlx5_wq_cyc_missing(struct mlx5_wq_cyc *wq)
{
	return wq->sz - wq->cur_sz;
}

static inline int mlx5_wq_cyc_is_empty(struct mlx5_wq_cyc *wq)
{
	return !wq->cur_sz;
}

static inline void mlx5_wq_cyc_push(struct mlx5_wq_cyc *wq)
{
	wq->wqe_ctr++;
	wq->cur_sz++;
}

static inline void mlx5_wq_cyc_push_n(struct mlx5_wq_cyc *wq, u8 n)
{
	wq->wqe_ctr += n;
	wq->cur_sz += n;
}

static inline void mlx5_wq_cyc_pop(struct mlx5_wq_cyc *wq)
{
	wq->cur_sz--;
}

static inline void mlx5_wq_cyc_update_db_record(struct mlx5_wq_cyc *wq)
{
	*wq->db = cpu_to_be32(wq->wqe_ctr);
}

//把一个不断递增的计数器 ctr 映射到环形工作队列 wq 的当前索引位置
static inline u16 mlx5_wq_cyc_ctr2ix(struct mlx5_wq_cyc *wq, u16 ctr)
{
	return ctr & wq->fbc.sz_m1;
}

static inline u16 mlx5_wq_cyc_get_head(struct mlx5_wq_cyc *wq)
{
	return mlx5_wq_cyc_ctr2ix(wq, wq->wqe_ctr);
}

static inline u16 mlx5_wq_cyc_get_tail(struct mlx5_wq_cyc *wq)
{
	return mlx5_wq_cyc_ctr2ix(wq, wq->wqe_ctr - wq->cur_sz);
}

static inline void *mlx5_wq_cyc_get_wqe(struct mlx5_wq_cyc *wq, u16 ix)
{
	return mlx5_frag_buf_get_wqe(&wq->fbc, ix);
}

static inline u16 mlx5_wq_cyc_get_contig_wqebbs(struct mlx5_wq_cyc *wq, u16 ix)
{
	return mlx5_frag_buf_get_idx_last_contig_stride(&wq->fbc, ix) - ix + 1;
}

static inline int mlx5_wq_cyc_cc_bigger(u16 cc1, u16 cc2)
{
	int equal   = (cc1 == cc2);
	int smaller = 0x8000 & (cc1 - cc2);

	return !equal && !smaller;
}

static inline u16 mlx5_wq_cyc_get_counter(struct mlx5_wq_cyc *wq)
{
	return wq->wqe_ctr;
}

static inline u32 mlx5_cqwq_get_size(struct mlx5_cqwq *wq)
{
	return wq->fbc.sz_m1 + 1;
}

static inline u8 mlx5_cqwq_get_log_stride_size(struct mlx5_cqwq *wq)
{
	return wq->fbc.log_stride;
}

static inline u32 mlx5_cqwq_ctr2ix(struct mlx5_cqwq *wq, u32 ctr)
{
	return ctr & wq->fbc.sz_m1;
}

static inline u32 mlx5_cqwq_get_ci(struct mlx5_cqwq *wq)
{
	return mlx5_cqwq_ctr2ix(wq, wq->cc);
}

static inline struct mlx5_cqe64 *mlx5_cqwq_get_wqe(struct mlx5_cqwq *wq, u32 ix)
{
	struct mlx5_cqe64 *cqe = mlx5_frag_buf_get_wqe(&wq->fbc, ix);

	/* For 128B CQEs the data is in the last 64B */
	cqe += wq->fbc.log_stride == 7;

	return cqe;
}

static inline u32 mlx5_cqwq_get_ctr_wrap_cnt(struct mlx5_cqwq *wq, u32 ctr)
{
	return ctr >> wq->fbc.log_sz;
}

static inline u32 mlx5_cqwq_get_wrap_cnt(struct mlx5_cqwq *wq)
{
	return mlx5_cqwq_get_ctr_wrap_cnt(wq, wq->cc);
}
//增加 CQ consumer index，表示消费了一个 CQE
static inline void mlx5_cqwq_pop(struct mlx5_cqwq *wq)
{
	wq->cc++;
}

//将软件端处理完的 Completion Queue Entry（CQE）个数 wq->cc 写入 Doorbell Record（wq->db），告诉硬件：
//我已经处理了 N 个 CQE，现在这些槽位你可以重用了
static inline void mlx5_cqwq_update_db_record(struct mlx5_cqwq *wq)
{
	*wq->db = cpu_to_be32(wq->cc & 0xffffff);
}
//从 Completion Queue (CQ) 获取下一个有效 CQE, 只有当 CQE 中的 owner 位表明数据是硬件新写入的才会返回有效指针
static inline struct mlx5_cqe64 *mlx5_cqwq_get_cqe(struct mlx5_cqwq *wq)
{
	//获取当前CI consumer index
	u32 ci = mlx5_cqwq_get_ci(wq);
	//获取该索引对应的 CQE 指针,这个结构就是 HW 写入的完成事件（TX/RX 完成）
	struct mlx5_cqe64 *cqe = mlx5_cqwq_get_wqe(wq, ci);
	//owner bit 用来区分这个 CQE 属于硬件写入的当前轮次还是上一轮被消费的旧数据
	u8 cqe_ownership_bit = cqe->op_own & MLX5_CQE_OWNER_MASK;
	//表示软件认为现在在偶数轮 or 奇数轮
	u8 sw_ownership_val = mlx5_cqwq_get_wrap_cnt(wq) & 1;
	//判断是否是新 CQE（是否可以读取） 返回 NULL，表示目前没有可用的 CQE，poll 函数会停下或等待下一次
	if (cqe_ownership_bit != sw_ownership_val)
		return NULL;

	/* 保证cpu之后的读取都是最新的 */
	dma_rmb();

	return cqe;
}

static inline u32 mlx5_wq_ll_get_size(struct mlx5_wq_ll *wq)
{
	return (u32)wq->fbc.sz_m1 + 1;
}

static inline int mlx5_wq_ll_is_full(struct mlx5_wq_ll *wq)
{
	return wq->cur_sz == wq->fbc.sz_m1;
}

static inline int mlx5_wq_ll_is_empty(struct mlx5_wq_ll *wq)
{
	return !wq->cur_sz;
}

static inline int mlx5_wq_ll_missing(struct mlx5_wq_ll *wq)
{
	return wq->fbc.sz_m1 - wq->cur_sz;
}

static inline void *mlx5_wq_ll_get_wqe(struct mlx5_wq_ll *wq, u16 ix)
{
	return mlx5_frag_buf_get_wqe(&wq->fbc, ix);
}

static inline u16 mlx5_wq_ll_get_wqe_next_ix(struct mlx5_wq_ll *wq, u16 ix)
{
	struct mlx5_wqe_srq_next_seg *wqe = mlx5_wq_ll_get_wqe(wq, ix);

	return be16_to_cpu(wqe->next_wqe_index);
}

static inline void mlx5_wq_ll_push(struct mlx5_wq_ll *wq, u16 head_next)
{
	wq->head = head_next;
	wq->wqe_ctr++;
	wq->cur_sz++;
}

static inline void mlx5_wq_ll_pop(struct mlx5_wq_ll *wq, __be16 ix,
				  __be16 *next_tail_next)
{
	*wq->tail_next = ix;
	wq->tail_next = next_tail_next;
	wq->cur_sz--;
}

static inline void mlx5_wq_ll_update_db_record(struct mlx5_wq_ll *wq)
{
	*wq->db = cpu_to_be32(wq->wqe_ctr);
}

static inline u16 mlx5_wq_ll_get_head(struct mlx5_wq_ll *wq)
{
	return wq->head;
}

static inline u16 mlx5_wq_ll_get_counter(struct mlx5_wq_ll *wq)
{
	return wq->wqe_ctr;
}

#endif /* __MLX5_WQ_H__ */
