/*
 * Copyright (c) 2015-2016, Mellanox Technologies. All rights reserved.
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

#include <linux/tcp.h>
#include <linux/if_vlan.h>
#include <net/geneve.h>
#include <net/dsfield.h>
#include "en.h"
#include "en/txrx.h"
#include "ipoib/ipoib.h"
#include "en_accel/en_accel.h"
#include "en_accel/ipsec_rxtx.h"
#include "en/ptp.h"

static void mlx5e_dma_unmap_wqe_err(struct mlx5e_txqsq *sq, u8 num_dma)
{
	int i;

	for (i = 0; i < num_dma; i++) {
		struct mlx5e_sq_dma *last_pushed_dma =
			mlx5e_dma_get(sq, --sq->dma_fifo_pc);

		mlx5e_tx_dma_unmap(sq->pdev, last_pushed_dma);
	}
}

#ifdef CONFIG_MLX5_CORE_EN_DCB
static inline int mlx5e_get_dscp_up(struct mlx5e_priv *priv, struct sk_buff *skb)
{
	int dscp_cp = 0;

	if (skb->protocol == htons(ETH_P_IP))
		dscp_cp = ipv4_get_dsfield(ip_hdr(skb)) >> 2;
	else if (skb->protocol == htons(ETH_P_IPV6))
		dscp_cp = ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;

	return priv->dcbx_dp.dscp2prio[dscp_cp];
}
#endif

static u16 mlx5e_select_ptpsq(struct net_device *dev, struct sk_buff *skb)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int up = 0;

	if (!netdev_get_num_tc(dev))
		goto return_txq;

#ifdef CONFIG_MLX5_CORE_EN_DCB
	if (priv->dcbx_dp.trust_state == MLX5_QPTS_TRUST_DSCP)
		up = mlx5e_get_dscp_up(priv, skb);
	else
#endif
		if (skb_vlan_tag_present(skb))
			up = skb_vlan_tag_get_prio(skb);

return_txq:
	return priv->port_ptp_tc2realtxq[up];
}

static int mlx5e_select_htb_queue(struct mlx5e_priv *priv, struct sk_buff *skb,
				  u16 htb_maj_id)
{
	u16 classid;

	if ((TC_H_MAJ(skb->priority) >> 16) == htb_maj_id)
		classid = TC_H_MIN(skb->priority);
	else
		classid = READ_ONCE(priv->htb.defcls);

	if (!classid)
		return 0;

	return mlx5e_get_txq_by_classid(priv, classid);
}

u16 mlx5e_select_queue(struct net_device *dev, struct sk_buff *skb,
		       struct net_device *sb_dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int num_tc_x_num_ch;
	int txq_ix;
	int up = 0;
	int ch_ix;

	/* Sync with mlx5e_update_num_tc_x_num_ch - avoid refetching. */
	num_tc_x_num_ch = READ_ONCE(priv->num_tc_x_num_ch);
	if (unlikely(dev->real_num_tx_queues > num_tc_x_num_ch)) {
		struct mlx5e_ptp *ptp_channel;

		/* Order maj_id before defcls - pairs with mlx5e_htb_root_add. */
		u16 htb_maj_id = smp_load_acquire(&priv->htb.maj_id);

		if (unlikely(htb_maj_id)) {
			txq_ix = mlx5e_select_htb_queue(priv, skb, htb_maj_id);
			if (txq_ix > 0)
				return txq_ix;
		}

		ptp_channel = READ_ONCE(priv->channels.ptp);
		if (unlikely(ptp_channel &&
			     test_bit(MLX5E_PTP_STATE_TX, ptp_channel->state) &&
			     mlx5e_use_ptpsq(skb)))
			return mlx5e_select_ptpsq(dev, skb);

		txq_ix = netdev_pick_tx(dev, skb, NULL);
		/* Fix netdev_pick_tx() not to choose ptp_channel and HTB txqs.
		 * If they are selected, switch to regular queues.
		 * Driver to select these queues only at mlx5e_select_ptpsq()
		 * and mlx5e_select_htb_queue().
		 */
		if (unlikely(txq_ix >= num_tc_x_num_ch))
			txq_ix %= num_tc_x_num_ch;
	} else {
		txq_ix = netdev_pick_tx(dev, skb, NULL);
	}

	if (!netdev_get_num_tc(dev))
		return txq_ix;

#ifdef CONFIG_MLX5_CORE_EN_DCB
	if (priv->dcbx_dp.trust_state == MLX5_QPTS_TRUST_DSCP)
		up = mlx5e_get_dscp_up(priv, skb);
	else
#endif
		if (skb_vlan_tag_present(skb))
			up = skb_vlan_tag_get_prio(skb);

	/* Normalize any picked txq_ix to [0, num_channels),
	 * So we can return a txq_ix that matches the channel and
	 * packet UP.
	 */
	ch_ix = priv->txq2sq[txq_ix]->ch_ix;

	return priv->channel_tc2realtxq[ch_ix][up];
}

static inline int mlx5e_skb_l2_header_offset(struct sk_buff *skb)
{
#define MLX5E_MIN_INLINE (ETH_HLEN + VLAN_HLEN)

	return max(skb_network_offset(skb), MLX5E_MIN_INLINE);
}

static inline int mlx5e_skb_l3_header_offset(struct sk_buff *skb)
{
	if (skb_transport_header_was_set(skb))
		return skb_transport_offset(skb);
	else
		return mlx5e_skb_l2_header_offset(skb);
}
// 内联长度计算
static inline u16 mlx5e_calc_min_inline(enum mlx5_inline_modes mode,
					struct sk_buff *skb)
{
	u16 hlen;

	switch (mode) {
	case MLX5_INLINE_MODE_NONE:
		return 0;
	case MLX5_INLINE_MODE_TCP_UDP:
		hlen = eth_get_headlen(skb->dev, skb->data, skb_headlen(skb));
		if (hlen == ETH_HLEN && !skb_vlan_tag_present(skb))
			hlen += VLAN_HLEN;
		break;
	case MLX5_INLINE_MODE_IP:
		hlen = mlx5e_skb_l3_header_offset(skb);
		break;
	case MLX5_INLINE_MODE_L2:
	default:
		hlen = mlx5e_skb_l2_header_offset(skb);
	}
	return min_t(u16, hlen, skb_headlen(skb));
}

static inline void mlx5e_insert_vlan(void *start, struct sk_buff *skb, u16 ihs)
{
	struct vlan_ethhdr *vhdr = (struct vlan_ethhdr *)start;
	int cpy1_sz = 2 * ETH_ALEN;
	int cpy2_sz = ihs - cpy1_sz;

	memcpy(vhdr, skb->data, cpy1_sz);
	vhdr->h_vlan_proto = skb->vlan_proto;
	vhdr->h_vlan_TCI = cpu_to_be16(skb_vlan_tag_get(skb));
	memcpy(&vhdr->h_vlan_encapsulated_proto, skb->data + cpy1_sz, cpy2_sz);
}

//根据 skb 是否需要 IPsec、TLS、封装或普通校验和 offload，设置 WQE 的 checksum 标志，指示硬件执行对应的加速任务
/* 这个函数填充 checksum offload 相关的字段；
	•	根据 skb 中是否需要 checksum offload（例如 CHECKSUM_PARTIAL），填入：
	•	L3/L4 协议类型（IP/TCP/UDP）；
	•	起始偏移；
	•	标记是否启用 TSO（大包分片 offload）；
	•	会设置 cs_flags 和 inline_hdr.sz 等字段
 */
static inline void
mlx5e_txwqe_build_eseg_csum(struct mlx5e_txqsq *sq, struct sk_buff *skb,
			    struct mlx5e_accel_tx_state *accel,
			    struct mlx5_wqe_eth_seg *eseg)
{
	if (unlikely(mlx5e_ipsec_txwqe_build_eseg_csum(sq, skb, eseg)))
		return;

	if (likely(skb->ip_summed == CHECKSUM_PARTIAL)) {
		eseg->cs_flags = MLX5_ETH_WQE_L3_CSUM;
		if (skb->encapsulation) {
			eseg->cs_flags |= MLX5_ETH_WQE_L3_INNER_CSUM |
					  MLX5_ETH_WQE_L4_INNER_CSUM;
			sq->stats->csum_partial_inner++;
		} else {
			eseg->cs_flags |= MLX5_ETH_WQE_L4_CSUM;
			sq->stats->csum_partial++;
		}
#ifdef CONFIG_MLX5_EN_TLS
	} else if (unlikely(accel && accel->tls.tls_tisn)) {
		eseg->cs_flags = MLX5_ETH_WQE_L3_CSUM | MLX5_ETH_WQE_L4_CSUM;
		sq->stats->csum_partial++;
#endif
	} else
		sq->stats->csum_none++;
}

static inline u16
mlx5e_tx_get_gso_ihs(struct mlx5e_txqsq *sq, struct sk_buff *skb)
{
	struct mlx5e_sq_stats *stats = sq->stats;
	u16 ihs;

	if (skb->encapsulation) {
		ihs = skb_inner_transport_offset(skb) + inner_tcp_hdrlen(skb);
		stats->tso_inner_packets++;
		stats->tso_inner_bytes += skb->len - ihs;
	} else {
		if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4)
			ihs = skb_transport_offset(skb) + sizeof(struct udphdr);
		else
			ihs = skb_transport_offset(skb) + tcp_hdrlen(skb);
		stats->tso_packets++;
		stats->tso_bytes += skb->len - ihs;
	}

	return ihs;
}

//把 skb 中的数据（包括 head 和所有分页 frags）转换为 NIC 可识别的 DMA 地址段（WQE Data Segment），并保存每段的地址和长度
static inline int
mlx5e_txwqe_build_dsegs(struct mlx5e_txqsq *sq, struct sk_buff *skb,
			unsigned char *skb_data, u16 headlen,
			struct mlx5_wqe_data_seg *dseg)
{
	dma_addr_t dma_addr = 0;
	u8 num_dma          = 0;
	int i;
	//映射 head 数据（skb->data 部分）
	if (headlen) {
		//将头数据映射为物理地址
		dma_addr = dma_map_single(sq->pdev, skb_data, headlen, DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(sq->pdev, dma_addr)))
			goto dma_unmap_wqe_err;
		/址、LKey、长度写入 WQE 的 data segment/将地
		dseg->addr       = cpu_to_be64(dma_addr);
		dseg->lkey       = sq->mkey_be;
		dseg->byte_count = cpu_to_be32(headlen);
		//记录映射信息（用于以后 unmap）
		mlx5e_dma_push(sq, dma_addr, headlen, MLX5E_DMA_MAP_SINGLE);
		num_dma++;
		//移动 dseg 指针，为下一个 segment 做准备
		dseg++;
	}
	//映射分页数据（skb frags）
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {//遍历 skb_shinfo(skb)->frags[] 中的每个分页碎片（通常是 payload）
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		int fsz = skb_frag_size(frag);
		//将页内偏移数据映射为 DMA 地址
		dma_addr = skb_frag_dma_map(sq->pdev, frag, 0, fsz, DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(sq->pdev, dma_addr)))
			goto dma_unmap_wqe_err;
		
		dseg->addr       = cpu_to_be64(dma_addr);
		dseg->lkey       = sq->mkey_be;
		dseg->byte_count = cpu_to_be32(fsz);

		mlx5e_dma_push(sq, dma_addr, fsz, MLX5E_DMA_MAP_PAGE);
		num_dma++;
		dseg++;
	}
	//表示总共构造了几个 data segment
	return num_dma;

dma_unmap_wqe_err:
	mlx5e_dma_unmap_wqe_err(sq, num_dma);
	return -ENOMEM;
}

struct mlx5e_tx_attr {
	u32 num_bytes;
	//当前 skb 中除 header 以外的数据长度
	u16 headlen;
	//inline header size
	u16 ihs;
	//每个 TCP 分段的最大大小（Maximum Segment Size）
	__be16 mss;
	u16 insz;
	u8 opcode;
};

struct mlx5e_tx_wqe_attr {
	//总DS数量
	u16 ds_cnt;
	//inline 头部用掉的
	u16 ds_cnt_inl;
	//inline data segment 数量（比如 TLS/IPSec 的 inline 元数据段）
	u16 ds_cnt_ids;
	//需要的 WQE block 数量（通常一个 WQEBB 是 64B，等于 4 DS）
	u8 num_wqebbs;
};

// 选择 inline 策略
static u8
mlx5e_tx_wqe_inline_mode(struct mlx5e_txqsq *sq, struct sk_buff *skb,
			 struct mlx5e_accel_tx_state *accel)
{
	u8 mode;

#ifdef CONFIG_MLX5_EN_TLS
	if (accel && accel->tls.tls_tisn)
		return MLX5_INLINE_MODE_TCP_UDP;
#endif

	mode = sq->min_inline_mode;

	if (skb_vlan_tag_present(skb) &&
	    test_bit(MLX5E_SQ_STATE_VLAN_NEED_L2_INLINE, &sq->state))
		mode = max_t(u8, MLX5_INLINE_MODE_L2, mode);

	return mode;
}

//根据 skb 的内容（GSO 或普通包），准备好发送属性 attr，统计数据，决定用什么 opcode、inline 多少、MSS 多大、总长度等
//accel: 预先判断过的加速状态（如 TLS/IPSec）
static void mlx5e_sq_xmit_prepare(struct mlx5e_txqsq *sq, struct sk_buff *skb,
				  struct mlx5e_accel_tx_state *accel,
				  struct mlx5e_tx_attr *attr)
{
	struct mlx5e_sq_stats *stats = sq->stats;

	if (skb_is_gso(skb)) {
		u16 ihs = mlx5e_tx_get_gso_ihs(sq, skb);//根据是否封装获取包头大小

		*attr = (struct mlx5e_tx_attr) {
			.opcode    = MLX5_OPCODE_LSO,
			.mss       = cpu_to_be16(skb_shinfo(skb)->gso_size),
			.ihs       = ihs,
			.num_bytes = skb->len + (skb_shinfo(skb)->gso_segs - 1) * ihs,
			.headlen   = skb_headlen(skb) - ihs,
		};

		stats->packets += skb_shinfo(skb)->gso_segs;
	} else {
		u8 mode = mlx5e_tx_wqe_inline_mode(sq, skb, accel);
		u16 ihs = mlx5e_calc_min_inline(mode, skb);

		*attr = (struct mlx5e_tx_attr) {
			.opcode    = MLX5_OPCODE_SEND,
			.mss       = cpu_to_be16(0),
			.ihs       = ihs,
			.num_bytes = max_t(unsigned int, skb->len, ETH_ZLEN),
			.headlen   = skb_headlen(skb) - ihs,
		};

		stats->packets++;
	}

	attr->insz = mlx5e_accel_tx_ids_len(sq, accel);
	stats->bytes += attr->num_bytes;
}

//计算一个待发送的数据包（skb）在 TX 队列中所需的资源（WQE 属性）。这个计算是必要的，因为 WQE 是分段提交给硬件的，必须提前知道它会占用多少个数据段（DS）和 WQE 块（WQEBB）
static void mlx5e_sq_calc_wqe_attr(struct sk_buff *skb, const struct mlx5e_tx_attr *attr,
				   struct mlx5e_tx_wqe_attr *wqe_attr)
{
	u16 ds_cnt = MLX5E_TX_WQE_EMPTY_DS_COUNT;//初始化描述符数量，包含一个固定开销（比如控制段）
	u16 ds_cnt_inl = 0;//inline 头部数据所需的描述符数量
	u16 ds_cnt_ids = 0;//inline data segment（可能来自 TLS 等情况）所需的描述符数量
	//如果有额外的 inline 数据（insz > 0），那么要加上其对应的 inline 段的描述符数
	if (attr->insz)
		ds_cnt_ids = DIV_ROUND_UP(sizeof(struct mlx5_wqe_inline_seg) + attr->insz,
					  MLX5_SEND_WQE_DS);
	//计算整个 WQE 的描述符需求
	//!!attr->headlen: 如果存在 head 数据就加 1；nr_frags: SKB 的 page fragment 数，每个也会对应一个描述符；ds_cnt_ids: 上面计算的 inline segment 的描述符数
	ds_cnt += !!attr->headlen + skb_shinfo(skb)->nr_frags + ds_cnt_ids;
	//如果启用了 header inline（ihs：inline header size）
	if (attr->ihs) {
		u16 inl = attr->ihs - INL_HDR_START_SZ;//从 ihs 中减去固定开头大小

		if (skb_vlan_tag_present(skb))//如果包有 VLAN tag，还要加上 VLAN 头长度
			inl += VLAN_HLEN;

		ds_cnt_inl = DIV_ROUND_UP(inl, MLX5_SEND_WQE_DS);//将最终 inline 数据字节数换算成所需的 DS 数并加入总数中
		ds_cnt += ds_cnt_inl;
	}
	//最后把计算出来的结果填入 wqe_attr
	*wqe_attr = (struct mlx5e_tx_wqe_attr) {
		.ds_cnt     = ds_cnt,
		.ds_cnt_inl = ds_cnt_inl,
		.ds_cnt_ids = ds_cnt_ids,
		.num_wqebbs = DIV_ROUND_UP(ds_cnt, MLX5_SEND_WQEBB_NUM_DS),
	};
}

static void mlx5e_tx_skb_update_hwts_flags(struct sk_buff *skb)
{
	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP))
		skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
}

static void mlx5e_tx_check_stop(struct mlx5e_txqsq *sq)
{
	if (unlikely(!mlx5e_wqc_has_room_for(&sq->wq, sq->cc, sq->pc, sq->stop_room))) {
		netif_tx_stop_queue(sq->txq);
		sq->stats->stopped++;
	}
}

static void mlx5e_tx_flush(struct mlx5e_txqsq *sq)
{
	struct mlx5e_tx_wqe_info *wi;
	struct mlx5e_tx_wqe *wqe;
	u16 pi;

	/* Must not be called when a MPWQE session is active but empty. */
	mlx5e_tx_mpwqe_ensure_complete(sq);

	pi = mlx5_wq_cyc_ctr2ix(&sq->wq, sq->pc);
	wi = &sq->db.wqe_info[pi];

	*wi = (struct mlx5e_tx_wqe_info) {
		.num_wqebbs = 1,
	};

	wqe = mlx5e_post_nop(&sq->wq, sq->sqn, &sq->pc);
	mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, &wqe->ctrl);
}

static inline void
mlx5e_txwqe_complete(struct mlx5e_txqsq *sq, struct sk_buff *skb,
		     const struct mlx5e_tx_attr *attr,
		     const struct mlx5e_tx_wqe_attr *wqe_attr, u8 num_dma,
		     struct mlx5e_tx_wqe_info *wi, struct mlx5_wqe_ctrl_seg *cseg,
		     bool xmit_more)
{
	struct mlx5_wq_cyc *wq = &sq->wq;
	bool send_doorbell;

	*wi = (struct mlx5e_tx_wqe_info) {
		.skb = skb,
		.num_bytes = attr->num_bytes,
		.num_dma = num_dma,
		.num_wqebbs = wqe_attr->num_wqebbs,
		.num_fifo_pkts = 0,
	};

	cseg->opmod_idx_opcode = cpu_to_be32((sq->pc << 8) | attr->opcode);
	cseg->qpn_ds           = cpu_to_be32((sq->sqn << 8) | wqe_attr->ds_cnt);

	mlx5e_tx_skb_update_hwts_flags(skb);

	sq->pc += wi->num_wqebbs;

	mlx5e_tx_check_stop(sq);

	if (unlikely(sq->ptpsq)) {
		mlx5e_skb_cb_hwtstamp_init(skb);
		mlx5e_skb_fifo_push(&sq->ptpsq->skb_fifo, skb);
		if (!netif_tx_queue_stopped(sq->txq) &&
		    !mlx5e_skb_fifo_has_room(&sq->ptpsq->skb_fifo)) {
			netif_tx_stop_queue(sq->txq);
			sq->stats->stopped++;
		}
		skb_get(skb);
	}

	send_doorbell = __netdev_tx_sent_queue(sq->txq, attr->num_bytes, xmit_more);
	if (send_doorbell)
		mlx5e_notify_hw(wq, sq->pc, sq->uar_map, cseg);
}

//将一个 skb（socket buffer）真正填充为 WQE（Work Queue Entry）并发送
static void
mlx5e_sq_xmit_wqe(struct mlx5e_txqsq *sq, struct sk_buff *skb,
		  const struct mlx5e_tx_attr *attr, const struct mlx5e_tx_wqe_attr *wqe_attr,
		  struct mlx5e_tx_wqe *wqe, u16 pi, bool xmit_more)
{
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5_wqe_eth_seg  *eseg;
	struct mlx5_wqe_data_seg *dseg;
	struct mlx5e_tx_wqe_info *wi;

	struct mlx5e_sq_stats *stats = sq->stats;
	int num_dma;

	stats->xmit_more += xmit_more;

	/* fill wqe */
	wi   = &sq->db.wqe_info[pi];//获取当前 PI 对应的 WQE 元信息（如追踪是否 DMA 成功）
	//预先映射好的 WQE 空间中三部分
	cseg = &wqe->ctrl;
	eseg = &wqe->eth;
	dseg =  wqe->data;

	eseg->mss = attr->mss;
	//如果启用了 inline header，说明驱动要手动写入以太网头部
	if (attr->ihs) {
		if (skb_vlan_tag_present(skb)) {
			eseg->inline_hdr.sz |= cpu_to_be16(attr->ihs + VLAN_HLEN);
			mlx5e_insert_vlan(eseg->inline_hdr.start, skb, attr->ihs);//先 memcpy 原始头部到 start，然后在第 12 字节处插入 VLAN tag
			stats->added_vlan_packets++;
		} else {
			eseg->inline_hdr.sz |= cpu_to_be16(attr->ihs);
			memcpy(eseg->inline_hdr.start, skb->data, attr->ihs);//没有 VLAN，只复制原始以太网头部
		}
		dseg += wqe_attr->ds_cnt_inl;
	} else if (skb_vlan_tag_present(skb)) {
		//如果没有 inline，但有 VLAN：使用硬件的 VLAN 插入功能，NIC 会在数据真正发送时自动插入 VLAN
		eseg->insert.type = cpu_to_be16(MLX5_ETH_WQE_INSERT_VLAN);
		if (skb->vlan_proto == cpu_to_be16(ETH_P_8021AD))
			eseg->insert.type |= cpu_to_be16(MLX5_ETH_WQE_SVLAN);
		eseg->insert.vlan_tci = cpu_to_be16(skb_vlan_tag_get(skb));
		stats->added_vlan_packets++;
	}
	//跳过这些 reserved 段，准备填真正的 packet payload
	dseg += wqe_attr->ds_cnt_ids;
	//将 skb 中的数据映射为 DMA 地址；填写进多个 struct mlx5_wqe_data_seg 结构；返回实际使用的 DMA 段数量（失败时返回负数）
	num_dma = mlx5e_txwqe_build_dsegs(sq, skb, skb->data + attr->ihs,
					  attr->headlen, dseg);
	if (unlikely(num_dma < 0))
		goto err_drop;

	mlx5e_txwqe_complete(sq, skb, attr, wqe_attr, num_dma, wi, cseg, xmit_more);

	return;

err_drop:
	stats->dropped++;
	dev_kfree_skb_any(skb);
	mlx5e_tx_flush(sq);
}
//判断当前的 skb（待发送数据包）是否满足使用 MPWQE（Multi-Packet Work Queue Entry）模式的条件
static bool mlx5e_tx_skb_supports_mpwqe(struct sk_buff *skb, struct mlx5e_tx_attr *attr)
{
	return !skb_is_nonlinear(skb) && !skb_vlan_tag_present(skb) && !attr->ihs &&
	       !attr->insz;
}

static bool mlx5e_tx_mpwqe_same_eseg(struct mlx5e_txqsq *sq, struct mlx5_wqe_eth_seg *eseg)
{
	struct mlx5e_tx_mpwqe *session = &sq->mpwqe;

	/* Assumes the session is already running and has at least one packet. */
	return !memcmp(&session->wqe->eth, eseg, MLX5E_ACCEL_ESEG_LEN);
}
//启动一次 MPWQE 发送会话（multi-packet work queue entry）分配并初始化 WQE，准备批量发送多个小包
static void mlx5e_tx_mpwqe_session_start(struct mlx5e_txqsq *sq,
					 struct mlx5_wqe_eth_seg *eseg)
{
	struct mlx5e_tx_mpwqe *session = &sq->mpwqe;
	struct mlx5e_tx_wqe *wqe;
	u16 pi;
	//从发送队列中分配 WQE 空间
	pi = mlx5e_txqsq_get_next_pi(sq, MLX5E_TX_MPW_MAX_WQEBBS);//获取 sq 当前的下一个 PI（Producer Index）
	wqe = MLX5E_TX_FETCH_WQE(sq, pi);//wqe 是这次多包会话的 WQE 开头
	net_prefetchw(wqe->data);//预取 wqe->data 所指向的数据区域，以减少后续写入的缓存 miss

	*session = (struct mlx5e_tx_mpwqe) {
		.wqe = wqe,
		.bytes_count = 0,
		.ds_count = MLX5E_TX_WQE_EMPTY_DS_COUNT,
		.pkt_count = 0,
		.inline_on = 0,
	};
	//拷贝 eseg 的前面部分（到 mss 字段为止）,初始化 eth segment，用于整个 MPWQE 会话中的多个 skb
	memcpy(&session->wqe->eth, eseg, MLX5E_ACCEL_ESEG_LEN);

	sq->stats->mpwqe_blks++;
}

static bool mlx5e_tx_mpwqe_session_is_active(struct mlx5e_txqsq *sq)
{
	return sq->mpwqe.wqe;
}

static void mlx5e_tx_mpwqe_add_dseg(struct mlx5e_txqsq *sq, struct mlx5e_xmit_data *txd)
{
	struct mlx5e_tx_mpwqe *session = &sq->mpwqe;
	struct mlx5_wqe_data_seg *dseg;

	dseg = (struct mlx5_wqe_data_seg *)session->wqe + session->ds_count;

	session->pkt_count++;
	session->bytes_count += txd->len;

	dseg->addr = cpu_to_be64(txd->dma_addr);
	dseg->byte_count = cpu_to_be32(txd->len);
	dseg->lkey = sq->mkey_be;
	session->ds_count++;

	sq->stats->mpwqe_pkts++;
}
//用于提交和终结一个 MPWQE 会话的关键函数，它将聚合的多个小包一次性发出，并更新控制段、队列状态和统计信息
static struct mlx5_wqe_ctrl_seg *mlx5e_tx_mpwqe_session_complete(struct mlx5e_txqsq *sq)
{
	struct mlx5e_tx_mpwqe *session = &sq->mpwqe;
	u8 ds_count = session->ds_count;
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5e_tx_wqe_info *wi;
	u16 pi;

	cseg = &session->wqe->ctrl;
	cseg->opmod_idx_opcode = cpu_to_be32((sq->pc << 8) | MLX5_OPCODE_ENHANCED_MPSW);
	cseg->qpn_ds = cpu_to_be32((sq->sqn << 8) | ds_count);

	pi = mlx5_wq_cyc_ctr2ix(&sq->wq, sq->pc);//每个 WQE 在环形队列里有一个索引 pi
	wi = &sq->db.wqe_info[pi];
	//wqe_info 记录了：总共多少字节（用于统计）；占用了多少个 WQEBB（Work Queue Entry Block）；包含了多少个 skb（DMA 次数）；有多少个包是从 FIFO 中来的。
	*wi = (struct mlx5e_tx_wqe_info) {
		.skb = NULL,
		.num_bytes = session->bytes_count,
		.num_wqebbs = DIV_ROUND_UP(ds_count, MLX5_SEND_WQEBB_NUM_DS),
		.num_dma = session->pkt_count,
		.num_fifo_pkts = session->pkt_count,
	};
	//递增队列指针: pc 是 Producer Counter；根据实际占用的 WQEBB 数更新，下一次发包会用新的 WQE 空间
	sq->pc += wi->num_wqebbs;

	session->wqe = NULL;
	//检查是否已经填满发送队列，决定是否 netdev_stop_queue()；防止后续 enqueue 导致覆盖或溢出
	mlx5e_tx_check_stop(sq);

	return cseg;
}

static void
mlx5e_sq_xmit_mpwqe(struct mlx5e_txqsq *sq, struct sk_buff *skb,
		    struct mlx5_wqe_eth_seg *eseg, bool xmit_more)
{
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5e_xmit_data txd;

	txd.data = skb->data;
	txd.len = skb->len;

	txd.dma_addr = dma_map_single(sq->pdev, txd.data, txd.len, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(sq->pdev, txd.dma_addr)))
		goto err_unmap;

	if (!mlx5e_tx_mpwqe_session_is_active(sq)) {
		mlx5e_tx_mpwqe_session_start(sq, eseg);
	} else if (!mlx5e_tx_mpwqe_same_eseg(sq, eseg)) {
		mlx5e_tx_mpwqe_session_complete(sq);
		mlx5e_tx_mpwqe_session_start(sq, eseg);
	}

	sq->stats->xmit_more += xmit_more;
	//记录这次 DMA 映射的地址范围到发送队列（sq）的 DMA 映射栈中
	mlx5e_dma_push(sq, txd.dma_addr, txd.len, MLX5E_DMA_MAP_SINGLE);
	//将本次发送的 skb 入队到软件 FIFO 中，供后续释放或异常处理 这是一个环形队列，用来与 WQE 一一对应，保证能够查回 skb 指针 避免过早释放 skb，只有在发送完成（CQE）后才释放
	mlx5e_skb_fifo_push(&sq->db.skb_fifo, skb);
	//将该 skb 的数据段描述符 txd 添加到 MPWQE 的聚合结构中
	mlx5e_tx_mpwqe_add_dseg(sq, &txd);
	//更新 skb 的硬件时间戳相关标志
	mlx5e_tx_skb_update_hwts_flags(skb);

	if (unlikely(mlx5e_tx_mpwqe_is_full(&sq->mpwqe))) {
		/* Might stop the queue and affect the retval of __netdev_tx_sent_queue. */
		cseg = mlx5e_tx_mpwqe_session_complete(sq);

		if (__netdev_tx_sent_queue(sq->txq, txd.len, xmit_more))
			mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, cseg);
	} else if (__netdev_tx_sent_queue(sq->txq, txd.len, xmit_more)) {
		/* Might stop the queue, but we were asked to ring the doorbell anyway. */
		cseg = mlx5e_tx_mpwqe_session_complete(sq);

		mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, cseg);
	}

	return;

err_unmap:
	sq->stats->dropped++;
	dev_kfree_skb_any(skb);
	mlx5e_tx_flush(sq);
}

//确保某个发送队列 sq 中的 MPWQE 会话已经完成（flush）
void mlx5e_tx_mpwqe_ensure_complete(struct mlx5e_txqsq *sq)
{
	/* 如果当前不是使用 MPWQE 的工作负载，进入这个函数的情况是不太可能的 如果是 MPWQE 工作负载，这个检查 也不是非常关键 */
	if (unlikely(mlx5e_tx_mpwqe_session_is_active(sq)))
		mlx5e_tx_mpwqe_session_complete(sq);
}

//构造 TX WQE 的 Ethernet Segment（eseg）
//填充以太网段（eseg）的所有信息，包括加速 offload（如 TLS/IPsec）所需的字段，以及 checksum offload 信息
static void mlx5e_txwqe_build_eseg(struct mlx5e_priv *priv, struct mlx5e_txqsq *sq,
				   struct sk_buff *skb, struct mlx5e_accel_tx_state *accel,
				   struct mlx5_wqe_eth_seg *eseg, u16 ihs)
{
	mlx5e_accel_tx_eseg(priv, skb, eseg, ihs);
	mlx5e_txwqe_build_eseg_csum(sq, skb, accel, eseg);
}

//根据包的特征选择合适的发送路径（MPWQE 或普通 WQE），完成数据映射、构建 WQE、处理加速功能，并将数据下发给硬件发送
netdev_tx_t mlx5e_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_accel_tx_state accel = {};
	struct mlx5e_tx_wqe_attr wqe_attr;
	struct mlx5e_tx_attr attr;
	struct mlx5e_tx_wqe *wqe;
	struct mlx5e_txqsq *sq;
	u16 pi;
	//根据 skb 对应的队列映射选择要使用的 SQ
	sq = priv->txq2sq[skb_get_queue_mapping(skb)];
	if (unlikely(!sq)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* May send SKBs and WQEs. TLS/IPsec 加速处理 */
	if (unlikely(!mlx5e_accel_tx_begin(dev, sq, skb, &accel)))
		return NETDEV_TX_OK;
	//准备发送属性，填充 attr 结构（inline header、MSS、VLAN 等）
	mlx5e_sq_xmit_prepare(sq, skb, &accel, &attr);
	//判断是否使用 MPWQE 模式（multi-packet WQE）
	if (test_bit(MLX5E_SQ_STATE_MPWQE, &sq->state)) {
		if (mlx5e_tx_skb_supports_mpwqe(skb, &attr)) {
			struct mlx5_wqe_eth_seg eseg = {};

			mlx5e_txwqe_build_eseg(priv, sq, skb, &accel, &eseg, attr.ihs);
			//发送
			mlx5e_sq_xmit_mpwqe(sq, skb, &eseg, netdev_xmit_more());
			return NETDEV_TX_OK;
		}

		mlx5e_tx_mpwqe_ensure_complete(sq);//flush 当前 MPWQE 会话
	}
	//计算这个包将使用的 WQE 大小、所需 DS（描述符）数量
	mlx5e_sq_calc_wqe_attr(skb, &attr, &wqe_attr);
	//找到下一个合适的队列位置（pi）
	pi = mlx5e_txqsq_get_next_pi(sq, wqe_attr.num_wqebbs);
	//获取对应的 WQE 结构指针（实际上是 DMA 区里的地址）
	wqe = MLX5E_TX_FETCH_WQE(sq, pi);

	/* May update the WQE, but may not post other WQEs. 加速收尾处理（TLS/IPsec 尾段） */
	//如果启用了加密 offload，TLS/IPsec 相关 metadata 被写入 WQE 的 inline 部分
	//注意这里的 inline 是 TLS 的，不是普通 inline header
	mlx5e_accel_tx_finish(sq, wqe, &accel,
			      (struct mlx5_wqe_inline_seg *)(wqe->data + wqe_attr.ds_cnt_inl));
	//构建以太网段（Ethernet Segment）
	mlx5e_txwqe_build_eseg(priv, sq, skb, &accel, &wqe->eth, attr.ihs);
	//构建数据段并发送 映射数据段 填写 Control Segment 触发写 doorbell
	mlx5e_sq_xmit_wqe(sq, skb, &attr, &wqe_attr, wqe, pi, netdev_xmit_more());

	return NETDEV_TX_OK;
}

void mlx5e_sq_xmit_simple(struct mlx5e_txqsq *sq, struct sk_buff *skb, bool xmit_more)
{
	struct mlx5e_tx_wqe_attr wqe_attr;
	struct mlx5e_tx_attr attr;
	struct mlx5e_tx_wqe *wqe;
	u16 pi;

	mlx5e_sq_xmit_prepare(sq, skb, NULL, &attr);
	mlx5e_sq_calc_wqe_attr(skb, &attr, &wqe_attr);
	pi = mlx5e_txqsq_get_next_pi(sq, wqe_attr.num_wqebbs);
	wqe = MLX5E_TX_FETCH_WQE(sq, pi);
	mlx5e_txwqe_build_eseg_csum(sq, skb, NULL, &wqe->eth);
	mlx5e_sq_xmit_wqe(sq, skb, &attr, &wqe_attr, wqe, pi, xmit_more);
}

static void mlx5e_tx_wi_dma_unmap(struct mlx5e_txqsq *sq, struct mlx5e_tx_wqe_info *wi,
				  u32 *dma_fifo_cc)
{
	int i;

	for (i = 0; i < wi->num_dma; i++) {
		struct mlx5e_sq_dma *dma = mlx5e_dma_get(sq, (*dma_fifo_cc)++);

		mlx5e_tx_dma_unmap(sq->pdev, dma);
	}
}

static void mlx5e_consume_skb(struct mlx5e_txqsq *sq, struct sk_buff *skb,
			      struct mlx5_cqe64 *cqe, int napi_budget)
{
	//是否开启了硬件时间戳
	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)) {
		struct skb_shared_hwtstamps hwts = {};
		u64 ts = get_cqe_ts(cqe);//提取发送完成时的硬件时间戳
		//使用 ptp_cyc2time 和 clock 将网卡周期计数转换为系统时钟（ns）
		hwts.hwtstamp = mlx5e_cqe_ts_to_ns(sq->ptp_cyc2time, sq->clock, ts);
		//将时间戳写入 skb
		if (sq->ptpsq)
			mlx5e_skb_cb_hwtstamp_handler(skb, MLX5E_SKB_CB_CQE_HWTSTAMP,
						      hwts.hwtstamp, sq->ptpsq->cq_stats);//ptpsq 存在（启用了 PTP queue）：使用 PTP 专用回调
		else
			skb_tstamp_tx(skb, &hwts);//写时间戳
	}

	napi_consume_skb(skb, napi_budget);
}

static void mlx5e_tx_wi_consume_fifo_skbs(struct mlx5e_txqsq *sq, struct mlx5e_tx_wqe_info *wi,
					  struct mlx5_cqe64 *cqe, int napi_budget)
{
	int i;

	for (i = 0; i < wi->num_fifo_pkts; i++) {
		struct sk_buff *skb = mlx5e_skb_fifo_pop(&sq->db.skb_fifo);

		mlx5e_consume_skb(sq, skb, cqe, napi_budget);
	}
}

//检查当前 txq 是否因为 BQL、队列满、或 __QUEUE_STATE_STACK_XOFF 等状态被停止；
//如果已满足恢复条件，则会唤醒队列、清除 XOFF 标志；
void mlx5e_txqsq_wake(struct mlx5e_txqsq *sq)
{
	if (netif_tx_queue_stopped(sq->txq) &&
	    mlx5e_wqc_has_room_for(&sq->wq, sq->cc, sq->pc, sq->stop_room) &&
	    mlx5e_ptpsq_fifo_has_room(sq) &&
	    !test_bit(MLX5E_SQ_STATE_RECOVERING, &sq->state)) {
		netif_tx_wake_queue(sq->txq);
		sq->stats->wake++;
	}
}

bool mlx5e_poll_tx_cq(struct mlx5e_cq *cq, int napi_budget)
{
	struct mlx5e_sq_stats *stats;
	struct mlx5e_txqsq *sq;
	struct mlx5_cqe64 *cqe;
	u32 dma_fifo_cc;
	u32 nbytes;
	u16 npkts;
	u16 sqcc;
	int i;

	sq = container_of(cq, struct mlx5e_txqsq, cq);

	if (unlikely(!test_bit(MLX5E_SQ_STATE_ENABLED, &sq->state)))
		return false;

	cqe = mlx5_cqwq_get_cqe(&cq->wq);
	if (!cqe)
		return false;

	stats = sq->stats;
	npkts = 0;
	nbytes = 0;
	/* sq->cc 必须在调用 mlx5_cqwq_update_db_record 之后再更新，否则可能会发生 CQ 溢出（cq overrun）*/
	sqcc = sq->cc;

	/* 避免在每处理一个 CQE（完成队列项）时都修改 SQ（发送队列）的 cache line，减少 cache 脏写 */
	dma_fifo_cc = sq->dma_fifo_cc;
	i = 0;
	do {
		struct mlx5e_tx_wqe_info *wi;
		u16 wqe_counter;
		bool last_wqe;
		u16 ci;
		//增加cc
		mlx5_cqwq_pop(&cq->wq);
		//从CQE中取出对应的WQE编号
		wqe_counter = be16_to_cpu(cqe->wqe_counter);
		//处理这个 CQE 对应的 所有 WQE（可能多个）
		do {
			last_wqe = (sqcc == wqe_counter);//判断是否是该 CQE 的最后一个 WQE
			ci = mlx5_wq_cyc_ctr2ix(&sq->wq, sqcc);//将 SQ counter 转换成实际索引
			wi = &sq->db.wqe_info[ci];//获取对应的 WQE 元信息

			sqcc += wi->num_wqebbs;//增加 SQ 消费指针
			//存在skb
			if (likely(wi->skb)) {
				mlx5e_tx_wi_dma_unmap(sq, wi, &dma_fifo_cc);//取消 DMA 映射
				mlx5e_consume_skb(sq, wi->skb, cqe, napi_budget);

				npkts++;
				nbytes += wi->num_bytes;
				continue;
			}
			if (unlikely(mlx5e_ktls_tx_try_handle_resync_dump_comp(sq, wi, &dma_fifo_cc)))
				continue;
			//如果使用 FIFO 模式发送的多个 SKB（比如分散包或聚合包）
			if (wi->num_fifo_pkts) {
				mlx5e_tx_wi_dma_unmap(sq, wi, &dma_fifo_cc);
				//释放skb
				mlx5e_tx_wi_consume_fifo_skbs(sq, wi, cqe, napi_budget);

				npkts += wi->num_fifo_pkts;
				nbytes += wi->num_bytes;
			}
		} while (!last_wqe);
		//请求执行失败的 CQE
		if (unlikely(get_cqe_opcode(cqe) == MLX5_CQE_REQ_ERR)) {
			//如果当前没有处于恢复状态，就设置它，并进入恢复流程
			if (!test_and_set_bit(MLX5E_SQ_STATE_RECOVERING, &sq->state)) {
				mlx5e_dump_error_cqe(&sq->cq, sq->sqn, (struct mlx5_err_cqe *)cqe);
				mlx5_wq_cyc_wqe_dump(&sq->wq, ci, wi->num_wqebbs);
				//向工作队列提交一个恢复任务 recover_work
				queue_work(cq->priv->wq, &sq->recover_work);
			}
			stats->cqe_err++;
		}
	} while ((++i < MLX5E_TX_CQ_POLL_BUDGET) && (cqe = mlx5_cqwq_get_cqe(&cq->wq)));

	stats->cqes += i;
	//Doorbell Record
	mlx5_cqwq_update_db_record(&cq->wq);
	/* ensure cq space is freed before enabling more cqes, 确保 doorbell 写入操作执行 */
	wmb();
	//更新 发送队列的 DMA FIFO 消费指针
	sq->dma_fifo_cc = dma_fifo_cc;
	//更新发送队列（SQ）的 Consumer Counter
	sq->cc = sqcc;
	netdev_tx_completed_queue(sq->txq, npkts, nbytes);
	mlx5e_txqsq_wake(sq);
	return (i == MLX5E_TX_CQ_POLL_BUDGET);
}

static void mlx5e_tx_wi_kfree_fifo_skbs(struct mlx5e_txqsq *sq, struct mlx5e_tx_wqe_info *wi)
{
	int i;

	for (i = 0; i < wi->num_fifo_pkts; i++)
		dev_kfree_skb_any(mlx5e_skb_fifo_pop(&sq->db.skb_fifo));
}

void mlx5e_free_txqsq_descs(struct mlx5e_txqsq *sq)
{
	struct mlx5e_tx_wqe_info *wi;
	u32 dma_fifo_cc, nbytes = 0;
	u16 ci, sqcc, npkts = 0;

	sqcc = sq->cc;
	dma_fifo_cc = sq->dma_fifo_cc;

	while (sqcc != sq->pc) {
		ci = mlx5_wq_cyc_ctr2ix(&sq->wq, sqcc);
		wi = &sq->db.wqe_info[ci];

		sqcc += wi->num_wqebbs;

		if (likely(wi->skb)) {
			mlx5e_tx_wi_dma_unmap(sq, wi, &dma_fifo_cc);
			dev_kfree_skb_any(wi->skb);

			npkts++;
			nbytes += wi->num_bytes;
			continue;
		}

		if (unlikely(mlx5e_ktls_tx_try_handle_resync_dump_comp(sq, wi, &dma_fifo_cc)))
			continue;

		if (wi->num_fifo_pkts) {
			mlx5e_tx_wi_dma_unmap(sq, wi, &dma_fifo_cc);
			mlx5e_tx_wi_kfree_fifo_skbs(sq, wi);

			npkts += wi->num_fifo_pkts;
			nbytes += wi->num_bytes;
		}
	}

	sq->dma_fifo_cc = dma_fifo_cc;
	sq->cc = sqcc;

	netdev_tx_completed_queue(sq->txq, npkts, nbytes);
}

#ifdef CONFIG_MLX5_CORE_IPOIB
static inline void
mlx5i_txwqe_build_datagram(struct mlx5_av *av, u32 dqpn, u32 dqkey,
			   struct mlx5_wqe_datagram_seg *dseg)
{
	memcpy(&dseg->av, av, sizeof(struct mlx5_av));
	dseg->av.dqp_dct = cpu_to_be32(dqpn | MLX5_EXTENDED_UD_AV);
	dseg->av.key.qkey.qkey = cpu_to_be32(dqkey);
}

static void mlx5i_sq_calc_wqe_attr(struct sk_buff *skb,
				   const struct mlx5e_tx_attr *attr,
				   struct mlx5e_tx_wqe_attr *wqe_attr)
{
	u16 ds_cnt = sizeof(struct mlx5i_tx_wqe) / MLX5_SEND_WQE_DS;
	u16 ds_cnt_inl = 0;

	ds_cnt += !!attr->headlen + skb_shinfo(skb)->nr_frags;

	if (attr->ihs) {
		u16 inl = attr->ihs - INL_HDR_START_SZ;

		ds_cnt_inl = DIV_ROUND_UP(inl, MLX5_SEND_WQE_DS);
		ds_cnt += ds_cnt_inl;
	}

	*wqe_attr = (struct mlx5e_tx_wqe_attr) {
		.ds_cnt     = ds_cnt,
		.ds_cnt_inl = ds_cnt_inl,
		.num_wqebbs = DIV_ROUND_UP(ds_cnt, MLX5_SEND_WQEBB_NUM_DS),
	};
}

void mlx5i_sq_xmit(struct mlx5e_txqsq *sq, struct sk_buff *skb,
		   struct mlx5_av *av, u32 dqpn, u32 dqkey, bool xmit_more)
{
	struct mlx5e_tx_wqe_attr wqe_attr;
	struct mlx5e_tx_attr attr;
	struct mlx5i_tx_wqe *wqe;

	struct mlx5_wqe_datagram_seg *datagram;
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5_wqe_eth_seg  *eseg;
	struct mlx5_wqe_data_seg *dseg;
	struct mlx5e_tx_wqe_info *wi;

	struct mlx5e_sq_stats *stats = sq->stats;
	int num_dma;
	u16 pi;

	mlx5e_sq_xmit_prepare(sq, skb, NULL, &attr);
	mlx5i_sq_calc_wqe_attr(skb, &attr, &wqe_attr);

	pi = mlx5e_txqsq_get_next_pi(sq, wqe_attr.num_wqebbs);
	wqe = MLX5I_SQ_FETCH_WQE(sq, pi);

	stats->xmit_more += xmit_more;

	/* fill wqe */
	wi       = &sq->db.wqe_info[pi];
	cseg     = &wqe->ctrl;
	datagram = &wqe->datagram;
	eseg     = &wqe->eth;
	dseg     =  wqe->data;

	mlx5i_txwqe_build_datagram(av, dqpn, dqkey, datagram);

	mlx5e_txwqe_build_eseg_csum(sq, skb, NULL, eseg);

	eseg->mss = attr.mss;

	if (attr.ihs) {
		memcpy(eseg->inline_hdr.start, skb->data, attr.ihs);
		eseg->inline_hdr.sz = cpu_to_be16(attr.ihs);
		dseg += wqe_attr.ds_cnt_inl;
	}

	num_dma = mlx5e_txwqe_build_dsegs(sq, skb, skb->data + attr.ihs,
					  attr.headlen, dseg);
	if (unlikely(num_dma < 0))
		goto err_drop;

	mlx5e_txwqe_complete(sq, skb, &attr, &wqe_attr, num_dma, wi, cseg, xmit_more);

	return;

err_drop:
	stats->dropped++;
	dev_kfree_skb_any(skb);
	mlx5e_tx_flush(sq);
}
#endif
