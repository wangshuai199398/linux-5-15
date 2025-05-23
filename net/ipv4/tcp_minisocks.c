// SPDX-License-Identifier: GPL-2.0-only
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/workqueue.h>
#include <linux/static_key.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/xfrm.h>
#include <net/busy_poll.h>

static bool tcp_in_window(u32 seq, u32 end_seq, u32 s_win, u32 e_win)
{
	if (seq == s_win)
		return true;
	if (after(end_seq, s_win) && before(seq, e_win))
		return true;
	return seq == e_win && seq == end_seq;
}

static enum tcp_tw_status
tcp_timewait_check_oow_rate_limit(struct inet_timewait_sock *tw,
				  const struct sk_buff *skb, int mib_idx)
{
	struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);

	if (!tcp_oow_rate_limited(twsk_net(tw), skb, mib_idx,
				  &tcptw->tw_last_oow_ack_time)) {
		/* Send ACK. Note, we do not put the bucket,
		 * it will be released by caller.
		 */
		return TCP_TW_ACK;
	}

	/* We are rate-limiting, so just release the tw sock and drop skb. */
	inet_twsk_put(tw);
	return TCP_TW_SUCCESS;
}

/*
 * * Main purpose of TIME-WAIT state is to close connection gracefully,
 *   when one of ends sits in LAST-ACK or CLOSING retransmitting FIN
 *   (and, probably, tail of data) and one or more our ACKs are lost.
 * * What is TIME-WAIT timeout? It is associated with maximal packet
 *   lifetime in the internet, which results in wrong conclusion, that
 *   it is set to catch "old duplicate segments" wandering out of their path.
 *   It is not quite correct. This timeout is calculated so that it exceeds
 *   maximal retransmission timeout enough to allow to lose one (or more)
 *   segments sent by peer and our ACKs. This time may be calculated from RTO.
 * * When TIME-WAIT socket receives RST, it means that another end
 *   finally closed and we are allowed to kill TIME-WAIT too.
 * * Second purpose of TIME-WAIT is catching old duplicate segments.
 *   Well, certainly it is pure paranoia, but if we load TIME-WAIT
 *   with this semantics, we MUST NOT kill TIME-WAIT state with RSTs.
 * * If we invented some more clever way to catch duplicates
 *   (f.e. based on PAWS), we could truncate TIME-WAIT to several RTOs.
 *
 * The algorithm below is based on FORMAL INTERPRETATION of RFCs.
 * When you compare it to RFCs, please, read section SEGMENT ARRIVES
 * from the very beginning.
 *
 * NOTE. With recycling (and later with fin-wait-2) TW bucket
 * is _not_ stateless. It means, that strictly speaking we must
 * spinlock it. I do not want! Well, probability of misbehaviour
 * is ridiculously low and, seems, we could use some mb() tricks
 * to avoid misread sequence numbers, states etc.  --ANK
 *
 * We don't need to initialize tmp_out.sack_ok as we don't use the results
 */
enum tcp_tw_status
tcp_timewait_state_process(struct inet_timewait_sock *tw, struct sk_buff *skb,
			   const struct tcphdr *th)
{
	struct tcp_options_received tmp_opt;
	struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);
	bool paws_reject = false;

	tmp_opt.saw_tstamp = 0;
	if (th->doff > (sizeof(*th) >> 2) && tcptw->tw_ts_recent_stamp) {
		tcp_parse_options(twsk_net(tw), skb, &tmp_opt, 0, NULL);

		if (tmp_opt.saw_tstamp) {
			if (tmp_opt.rcv_tsecr)
				tmp_opt.rcv_tsecr -= tcptw->tw_ts_offset;
			tmp_opt.ts_recent	= tcptw->tw_ts_recent;
			tmp_opt.ts_recent_stamp	= tcptw->tw_ts_recent_stamp;
			paws_reject = tcp_paws_reject(&tmp_opt, th->rst);
		}
	}

	if (tw->tw_substate == TCP_FIN_WAIT2) {
		/* Just repeat all the checks of tcp_rcv_state_process() */

		/* Out of window, send ACK */
		if (paws_reject ||
		    !tcp_in_window(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq,
				   tcptw->tw_rcv_nxt,
				   tcptw->tw_rcv_nxt + tcptw->tw_rcv_wnd))
			return tcp_timewait_check_oow_rate_limit(
				tw, skb, LINUX_MIB_TCPACKSKIPPEDFINWAIT2);

		if (th->rst)
			goto kill;

		if (th->syn && !before(TCP_SKB_CB(skb)->seq, tcptw->tw_rcv_nxt))
			return TCP_TW_RST;

		/* Dup ACK? */
		if (!th->ack ||
		    !after(TCP_SKB_CB(skb)->end_seq, tcptw->tw_rcv_nxt) ||
		    TCP_SKB_CB(skb)->end_seq == TCP_SKB_CB(skb)->seq) {
			inet_twsk_put(tw);
			return TCP_TW_SUCCESS;
		}

		/* New data or FIN. If new data arrive after half-duplex close,
		 * reset.
		 */
		if (!th->fin ||
		    TCP_SKB_CB(skb)->end_seq != tcptw->tw_rcv_nxt + 1)
			return TCP_TW_RST;

		/* FIN arrived, enter true time-wait state. */
		tw->tw_substate	  = TCP_TIME_WAIT;
		tcptw->tw_rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		if (tmp_opt.saw_tstamp) {
			tcptw->tw_ts_recent_stamp = ktime_get_seconds();
			tcptw->tw_ts_recent	  = tmp_opt.rcv_tsval;
		}

		inet_twsk_reschedule(tw, TCP_TIMEWAIT_LEN);
		return TCP_TW_ACK;
	}

	/*
	 *	Now real TIME-WAIT state.
	 *
	 *	RFC 1122:
	 *	"When a connection is [...] on TIME-WAIT state [...]
	 *	[a TCP] MAY accept a new SYN from the remote TCP to
	 *	reopen the connection directly, if it:
	 *
	 *	(1)  assigns its initial sequence number for the new
	 *	connection to be larger than the largest sequence
	 *	number it used on the previous connection incarnation,
	 *	and
	 *
	 *	(2)  returns to TIME-WAIT state if the SYN turns out
	 *	to be an old duplicate".
	 */

	if (!paws_reject &&
	    (TCP_SKB_CB(skb)->seq == tcptw->tw_rcv_nxt &&
	     (TCP_SKB_CB(skb)->seq == TCP_SKB_CB(skb)->end_seq || th->rst))) {
		/* In window segment, it may be only reset or bare ack. */

		if (th->rst) {
			/* This is TIME_WAIT assassination, in two flavors.
			 * Oh well... nobody has a sufficient solution to this
			 * protocol bug yet.
			 */
			if (!READ_ONCE(twsk_net(tw)->ipv4.sysctl_tcp_rfc1337)) {
kill:
				inet_twsk_deschedule_put(tw);
				return TCP_TW_SUCCESS;
			}
		} else {
			inet_twsk_reschedule(tw, TCP_TIMEWAIT_LEN);
		}

		if (tmp_opt.saw_tstamp) {
			tcptw->tw_ts_recent	  = tmp_opt.rcv_tsval;
			tcptw->tw_ts_recent_stamp = ktime_get_seconds();
		}

		inet_twsk_put(tw);
		return TCP_TW_SUCCESS;
	}

	/* Out of window segment.

	   All the segments are ACKed immediately.

	   The only exception is new SYN. We accept it, if it is
	   not old duplicate and we are not in danger to be killed
	   by delayed old duplicates. RFC check is that it has
	   newer sequence number works at rates <40Mbit/sec.
	   However, if paws works, it is reliable AND even more,
	   we even may relax silly seq space cutoff.

	   RED-PEN: we violate main RFC requirement, if this SYN will appear
	   old duplicate (i.e. we receive RST in reply to SYN-ACK),
	   we must return socket to time-wait state. It is not good,
	   but not fatal yet.
	 */

	if (th->syn && !th->rst && !th->ack && !paws_reject &&
	    (after(TCP_SKB_CB(skb)->seq, tcptw->tw_rcv_nxt) ||
	     (tmp_opt.saw_tstamp &&
	      (s32)(tcptw->tw_ts_recent - tmp_opt.rcv_tsval) < 0))) {
		u32 isn = tcptw->tw_snd_nxt + 65535 + 2;
		if (isn == 0)
			isn++;
		TCP_SKB_CB(skb)->tcp_tw_isn = isn;
		return TCP_TW_SYN;
	}

	if (paws_reject)
		__NET_INC_STATS(twsk_net(tw), LINUX_MIB_PAWSESTABREJECTED);

	if (!th->rst) {
		/* In this case we must reset the TIMEWAIT timer.
		 *
		 * If it is ACKless SYN it may be both old duplicate
		 * and new good SYN with random sequence number <rcv_nxt.
		 * Do not reschedule in the last case.
		 */
		if (paws_reject || th->ack)
			inet_twsk_reschedule(tw, TCP_TIMEWAIT_LEN);

		return tcp_timewait_check_oow_rate_limit(
			tw, skb, LINUX_MIB_TCPACKSKIPPEDTIMEWAIT);
	}
	inet_twsk_put(tw);
	return TCP_TW_SUCCESS;
}
EXPORT_SYMBOL(tcp_timewait_state_process);

/*
 * Move a socket to time-wait or dead fin-wait-2 state.
 */
void tcp_time_wait(struct sock *sk, int state, int timeo)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	struct inet_timewait_sock *tw;
	struct inet_timewait_death_row *tcp_death_row = &sock_net(sk)->ipv4.tcp_death_row;

	tw = inet_twsk_alloc(sk, tcp_death_row, state);

	if (tw) {
		struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);
		const int rto = (icsk->icsk_rto << 2) - (icsk->icsk_rto >> 1);
		struct inet_sock *inet = inet_sk(sk);

		tw->tw_transparent	= inet->transparent;
		tw->tw_mark		= sk->sk_mark;
		tw->tw_priority		= sk->sk_priority;
		tw->tw_rcv_wscale	= tp->rx_opt.rcv_wscale;
		tcptw->tw_rcv_nxt	= tp->rcv_nxt;
		tcptw->tw_snd_nxt	= tp->snd_nxt;
		tcptw->tw_rcv_wnd	= tcp_receive_window(tp);
		tcptw->tw_ts_recent	= tp->rx_opt.ts_recent;
		tcptw->tw_ts_recent_stamp = tp->rx_opt.ts_recent_stamp;
		tcptw->tw_ts_offset	= tp->tsoffset;
		tcptw->tw_last_oow_ack_time = 0;
		tcptw->tw_tx_delay	= tp->tcp_tx_delay;
#if IS_ENABLED(CONFIG_IPV6)
		if (tw->tw_family == PF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(sk);

			tw->tw_v6_daddr = sk->sk_v6_daddr;
			tw->tw_v6_rcv_saddr = sk->sk_v6_rcv_saddr;
			tw->tw_tclass = np->tclass;
			tw->tw_flowlabel = be32_to_cpu(np->flow_label & IPV6_FLOWLABEL_MASK);
			tw->tw_txhash = sk->sk_txhash;
			tw->tw_ipv6only = sk->sk_ipv6only;
		}
#endif

#ifdef CONFIG_TCP_MD5SIG
		/*
		 * The timewait bucket does not have the key DB from the
		 * sock structure. We just make a quick copy of the
		 * md5 key being used (if indeed we are using one)
		 * so the timewait ack generating code has the key.
		 */
		do {
			tcptw->tw_md5_key = NULL;
			if (static_branch_unlikely(&tcp_md5_needed)) {
				struct tcp_md5sig_key *key;

				key = tp->af_specific->md5_lookup(sk, sk);
				if (key) {
					tcptw->tw_md5_key = kmemdup(key, sizeof(*key), GFP_ATOMIC);
					BUG_ON(tcptw->tw_md5_key && !tcp_alloc_md5sig_pool());
				}
			}
		} while (0);
#endif

		/* Get the TIME_WAIT timeout firing. */
		if (timeo < rto)
			timeo = rto;

		if (state == TCP_TIME_WAIT)
			timeo = TCP_TIMEWAIT_LEN;

		/* tw_timer is pinned, so we need to make sure BH are disabled
		 * in following section, otherwise timer handler could run before
		 * we complete the initialization.
		 */
		local_bh_disable();
		inet_twsk_schedule(tw, timeo);
		/* Linkage updates.
		 * Note that access to tw after this point is illegal.
		 */
		inet_twsk_hashdance(tw, sk, &tcp_hashinfo);
		local_bh_enable();
	} else {
		/* Sorry, if we're out of memory, just CLOSE this
		 * socket up.  We've got bigger problems than
		 * non-graceful socket closings.
		 */
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPTIMEWAITOVERFLOW);
	}

	tcp_update_metrics(sk);
	tcp_done(sk);
}
EXPORT_SYMBOL(tcp_time_wait);

void tcp_twsk_destructor(struct sock *sk)
{
#ifdef CONFIG_TCP_MD5SIG
	if (static_branch_unlikely(&tcp_md5_needed)) {
		struct tcp_timewait_sock *twsk = tcp_twsk(sk);

		if (twsk->tw_md5_key)
			kfree_rcu(twsk->tw_md5_key, rcu);
	}
#endif
}
EXPORT_SYMBOL_GPL(tcp_twsk_destructor);

/* Warning : This function is called without sk_listener being locked.
 * Be sure to read socket fields once, as their value could change under us.
 */
void tcp_openreq_init_rwin(struct request_sock *req,
			   const struct sock *sk_listener,
			   const struct dst_entry *dst)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	const struct tcp_sock *tp = tcp_sk(sk_listener);
	int full_space = tcp_full_space(sk_listener);
	u32 window_clamp;
	__u8 rcv_wscale;
	u32 rcv_wnd;
	int mss;

	mss = tcp_mss_clamp(tp, dst_metric_advmss(dst));
	window_clamp = READ_ONCE(tp->window_clamp);
	/* Set this up on the first call only */
	req->rsk_window_clamp = window_clamp ? : dst_metric(dst, RTAX_WINDOW);

	/* limit the window selection if the user enforce a smaller rx buffer */
	if (sk_listener->sk_userlocks & SOCK_RCVBUF_LOCK &&
	    (req->rsk_window_clamp > full_space || req->rsk_window_clamp == 0))
		req->rsk_window_clamp = full_space;

	rcv_wnd = tcp_rwnd_init_bpf((struct sock *)req);
	if (rcv_wnd == 0)
		rcv_wnd = dst_metric(dst, RTAX_INITRWND);
	else if (full_space < rcv_wnd * mss)
		full_space = rcv_wnd * mss;

	/* tcp_full_space because it is guaranteed to be the first packet */
	tcp_select_initial_window(sk_listener, full_space,
		mss - (ireq->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0),
		&req->rsk_rcv_wnd,
		&req->rsk_window_clamp,
		ireq->wscale_ok,
		&rcv_wscale,
		rcv_wnd);
	ireq->rcv_wscale = rcv_wscale;
}
EXPORT_SYMBOL(tcp_openreq_init_rwin);

static void tcp_ecn_openreq_child(struct tcp_sock *tp,
				  const struct request_sock *req)
{
	tp->ecn_flags = inet_rsk(req)->ecn_ok ? TCP_ECN_OK : 0;
}

void tcp_ca_openreq_child(struct sock *sk, const struct dst_entry *dst)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	u32 ca_key = dst_metric(dst, RTAX_CC_ALGO);
	bool ca_got_dst = false;

	if (ca_key != TCP_CA_UNSPEC) {
		const struct tcp_congestion_ops *ca;

		rcu_read_lock();
		ca = tcp_ca_find_key(ca_key);
		if (likely(ca && bpf_try_module_get(ca, ca->owner))) {
			icsk->icsk_ca_dst_locked = tcp_ca_dst_locked(dst);
			icsk->icsk_ca_ops = ca;
			ca_got_dst = true;
		}
		rcu_read_unlock();
	}

	/* If no valid choice made yet, assign current system default ca. */
	if (!ca_got_dst &&
	    (!icsk->icsk_ca_setsockopt ||
	     !bpf_try_module_get(icsk->icsk_ca_ops, icsk->icsk_ca_ops->owner)))
		tcp_assign_congestion_control(sk);

	tcp_set_ca_state(sk, TCP_CA_Open);
}
EXPORT_SYMBOL_GPL(tcp_ca_openreq_child);

static void smc_check_reset_syn_req(struct tcp_sock *oldtp,
				    struct request_sock *req,
				    struct tcp_sock *newtp)
{
#if IS_ENABLED(CONFIG_SMC)
	struct inet_request_sock *ireq;

	if (static_branch_unlikely(&tcp_have_smc)) {
		ireq = inet_rsk(req);
		if (oldtp->syn_smc && !ireq->smc_ok)
			newtp->syn_smc = 0;
	}
#endif
}

/* 监听 socket (sk) 的 tcp_sock 结构（简称 tp）中已经包含很多默认配置，可以直接继承到新的 socket，不必重复初始化
 */
struct sock *tcp_create_openreq_child(const struct sock *sk,
				      struct request_sock *req,
				      struct sk_buff *skb)
{
	struct sock *newsk = inet_csk_clone_lock(sk, req, GFP_ATOMIC);
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct tcp_request_sock *treq = tcp_rsk(req);
	struct inet_connection_sock *newicsk;
	struct tcp_sock *oldtp, *newtp;
	u32 seq;

	if (!newsk)
		return NULL;

	newicsk = inet_csk(newsk);
	newtp = tcp_sk(newsk);
	oldtp = tcp_sk(sk);
	//处理 SMC（Shared Memory Communications，微软的共享内存通信技术）相关的状态检查和复位
	smc_check_reset_syn_req(oldtp, req, newtp);

	/* Now setup tcp_sock */
	newtp->pred_flags = 0;

	seq = treq->rcv_isn + 1;
	newtp->rcv_wup = seq;
	WRITE_ONCE(newtp->copied_seq, seq);
	WRITE_ONCE(newtp->rcv_nxt, seq);
	newtp->segs_in = 1;

	seq = treq->snt_isn + 1;
	newtp->snd_sml = newtp->snd_una = seq;
	WRITE_ONCE(newtp->snd_nxt, seq);
	newtp->snd_up = seq;

	INIT_LIST_HEAD(&newtp->tsq_node);
	INIT_LIST_HEAD(&newtp->tsorted_sent_queue);
	//初始化 拥塞窗口（Window Limiting，简称 WL） 相关状态
	tcp_init_wl(newtp, treq->rcv_isn);

	minmax_reset(&newtp->rtt_min, tcp_jiffies32, ~0U);
	newicsk->icsk_ack.lrcvtime = tcp_jiffies32;

	newtp->lsndtime = tcp_jiffies32;
	newsk->sk_txhash = treq->txhash;
	newtp->total_retrans = req->num_retrans;
	//初始化 TCP 传输定时器
	tcp_init_xmit_timers(newsk);
	WRITE_ONCE(newtp->write_seq, newtp->pushed_seq = treq->snt_isn + 1);
	//如果开启了 SO_KEEPALIVE 标志（即 SOCK_KEEPOPEN），就会启动或重置 TCP 的 Keepalive 定时器
	if (sock_flag(newsk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_timer(newsk,
					       keepalive_time_when(newtp));

	newtp->rx_opt.tstamp_ok = ireq->tstamp_ok;
	newtp->rx_opt.sack_ok = ireq->sack_ok;
	newtp->window_clamp = req->rsk_window_clamp;
	newtp->rcv_ssthresh = req->rsk_rcv_wnd;
	newtp->rcv_wnd = req->rsk_rcv_wnd;
	newtp->rx_opt.wscale_ok = ireq->wscale_ok;
	if (newtp->rx_opt.wscale_ok) {
		newtp->rx_opt.snd_wscale = ireq->snd_wscale;
		newtp->rx_opt.rcv_wscale = ireq->rcv_wscale;
	} else {
		newtp->rx_opt.snd_wscale = newtp->rx_opt.rcv_wscale = 0;
		newtp->window_clamp = min(newtp->window_clamp, 65535U);
	}
	newtp->snd_wnd = ntohs(tcp_hdr(skb)->window) << newtp->rx_opt.snd_wscale;
	newtp->max_window = newtp->snd_wnd;

	if (newtp->rx_opt.tstamp_ok) {
		newtp->rx_opt.ts_recent = READ_ONCE(req->ts_recent);
		newtp->rx_opt.ts_recent_stamp = ktime_get_seconds();
		newtp->tcp_header_len = sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
	} else {
		newtp->rx_opt.ts_recent_stamp = 0;
		newtp->tcp_header_len = sizeof(struct tcphdr);
	}
	if (req->num_timeout) {
		newtp->undo_marker = treq->snt_isn;
		newtp->retrans_stamp = div_u64(treq->snt_synack,
					       USEC_PER_SEC / TCP_TS_HZ);
	}
	newtp->tsoffset = treq->ts_off;
#ifdef CONFIG_TCP_MD5SIG
	newtp->md5sig_info = NULL;	/*XXX*/
	if (treq->af_specific->req_md5_lookup(sk, req_to_sk(req)))
		newtp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
#endif
	if (skb->len >= TCP_MSS_DEFAULT + newtp->tcp_header_len)
		newicsk->icsk_ack.last_seg_size = skb->len - newtp->tcp_header_len;
	newtp->rx_opt.mss_clamp = req->mss;
	//设置新连接支持的 ECN 标志
	tcp_ecn_openreq_child(newtp, req);
	newtp->fastopen_req = NULL;
	RCU_INIT_POINTER(newtp->fastopen_rsk, NULL);

	tcp_bpf_clone(sk, newsk);

	__TCP_INC_STATS(sock_net(sk), TCP_MIB_PASSIVEOPENS);

	return newsk;
}
EXPORT_SYMBOL(tcp_create_openreq_child);

/*
 * Process an incoming packet for SYN_RECV sockets represented as a
 * request_sock. Normally sk is the listener socket but for TFO it
 * points to the child socket.
 *
 * XXX (TFO) - The current impl contains a special check for ack
 * validation and inside tcp_v4_reqsk_send_ack(). Can we do better?
 *
 * We don't need to initialize tmp_opt.sack_ok as we don't use the results
 *
 * Note: If @fastopen is true, this can be called from process context.
 *       Otherwise, this is from BH context.
 */

struct sock *tcp_check_req(struct sock *sk, struct sk_buff *skb,
			   struct request_sock *req,
			   bool fastopen, bool *req_stolen)
{
	struct tcp_options_received tmp_opt;
	struct sock *child;
	const struct tcphdr *th = tcp_hdr(skb);
	__be32 flg = tcp_flag_word(th) & (TCP_FLAG_RST|TCP_FLAG_SYN|TCP_FLAG_ACK);
	//是否因为 PAWS（保护窗口避免旧数据包）机制而拒绝该包
	bool paws_reject = false;
	bool own_req;

	tmp_opt.saw_tstamp = 0;
	//TCP数据偏移字段表明有选项
	if (th->doff > (sizeof(struct tcphdr)>>2)) {
		//提取选项（如时间戳、窗口缩放等）
		tcp_parse_options(sock_net(sk), skb, &tmp_opt, 0, NULL);

		if (tmp_opt.saw_tstamp) {
			//从 req 中取出记录的时间戳
			tmp_opt.ts_recent = READ_ONCE(req->ts_recent);
			//修正 rcv_tsecr 的值以考虑 TSO 偏移
			if (tmp_opt.rcv_tsecr)
				tmp_opt.rcv_tsecr -= tcp_rsk(req)->ts_off;
			/* We do not store true stamp, but it is not required, it can be estimated (approximately) from another data. */
			//构造“时间戳上次收到时间”
			tmp_opt.ts_recent_stamp = ktime_get_seconds() - reqsk_timeout(req, TCP_RTO_MAX) / HZ;
			//判断时间戳是否合法（是否老包），如果不合法，说明是旧包（比如迟到的 SYN 重传），就可以忽略掉
			paws_reject = tcp_paws_reject(&tmp_opt, th->rst);
		}
	}

	//检查是否是重复SYN重传，如果当前包的SEQ和原始ISN一致，并且它是纯SYN，并且没有被PAWS拒绝，那说明这可能是客户端重发的SYN，你可以选择忽略掉，或者做某些idempotent处理
	if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn &&
	    flg == TCP_FLAG_SYN &&
	    !paws_reject) {
		/* 如果客户端的ACK不对（如窗口外、重复等），服务器重新发送SYN-ACK，期望客户端再回复正确的ACK
		 * 即便客户端的 SYN 中包含数据（违反规范），也会直接丢弃
		 * 重新传 SYN-ACK 的同时，重置超时重传定时器，和 fast retransmit 类似，避免过早放弃连接
		 * 客户端发出了SYN，收到了SYN-ACK，但ACK丢了，此时它会再发一个SYN。服务端看到重复的SYN，但自己还在SYN-RECV，这时就会重新发SYN-ACK，重置计时器，再等客户端ACK
		 */
		//是否要对同一客户端重传ACK或SYN-ACK进行限速，防止DoS或SYN flood，参数last_oow_ack_time是上次给该客户端重发ACK的时间
		if (!tcp_oow_rate_limited(sock_net(sk), skb,
					  LINUX_MIB_TCPACKSKIPPEDSYNRECV,
					  &tcp_rsk(req)->last_oow_ack_time) &&
		    !inet_rtx_syn_ack(sk, req)) {//尝试重传SYN-ACK报文，成功返回0
			unsigned long expires = jiffies;
			//返回一个当前最大重传超时时间
			expires += reqsk_timeout(req, TCP_RTO_MAX);
			if (!fastopen)
				//将req->rsk_timer加入定时器队列，并设置新的超时时间 expires；如果定时器已经在队列中，会更新它的超时点
				mod_timer_pending(&req->rsk_timer, expires);
			else
				req->rsk_timer.expires = expires;//只设置expires字段，启动时机延迟，由其他逻辑决定是否启动定时器

		}
		return NULL;
	}

	/* 假设攻击者发送了完全相同的 SYN 包
	   A: 收到 SYN，seq=7
	   B: 收到 SYN，seq=7
	   由于运气好，A 和 B 恰好都选择了初始发送序列号为 7
	   A: 发送 SYN|ACK，seq=7，ack_seq=8
	   B: 发送 SYN|ACK，seq=7，ack_seq=8
	   现在 A 收到 B 的 SYN|ACK，看起来完全合法。ACK 检查通过，序列号检查也通过，SYN 被截断，最终这个包被当作一个普通 ACK。
	   如果开启了 icsk->icsk_accept_queue.rskq_defer_accept，我们会悄悄丢弃这个裸 ACK；
	   否则，我们会直接建立连接。此时 A 和 B 这两个监听 socket 都建立了连接，然后……互相通信。8
	   注意：这个情况虽然存在，但既无害，又极其罕见
	   防御：
	   ACK 校验（tcp_ack）  防止接受伪造 ACK 建立连接
       ISN 加密            防止预测/伪造 SYN/ACK 序列号
       TCP 时间戳（PAWS）   检测并拒绝过期或伪造段
       defer_accept 策略   拒绝无数据 ACK 引发的“伪连接”
       Fast Open 特判      防止带数据的早期 ACK 被绕过校验
	 */
	//如果是ACK包，并且没有开启Fast Open，且ACK序列号不等于ISN+1，说明这个包不是合法的ACK包，返回监听 socket sk，让上层函数发一个TCP RST，表示这是个非法连接尝试，关闭连接
	//ack是对端发过来的报文seq+数据长度，也是下一个对端发过来的seq，seq是上一次自己发的set+数据长度
	if ((flg & TCP_FLAG_ACK) && !fastopen &&
	    (TCP_SKB_CB(skb)->ack_seq !=
	     tcp_rsk(req)->snt_isn + 1))
		return sk;

	/* 检查 rcv_tsecr（接收方时间戳回显）其实是个不错的主意。它相当于是 ACK 的一个扩展字段，如果其值太早或太晚（不合理）
	 * 在连接还没完全建立（非同步状态）时，就可以视为非法包 —— 应该立刻发 RST
	 */
	//时间戳太旧或者数据包序列号不在接收窗口内 判断数据包seq~end_seq是否落在预期接收窗口[rcv_nxt, rcv_nxt + rcv_wnd]范围内，如果不在窗口内，表示包失序、伪造、重复或非法，应该丢弃
	if (paws_reject || !tcp_in_window(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq,
					  tcp_rsk(req)->rcv_nxt, tcp_rsk(req)->rcv_nxt + req->rsk_rcv_wnd)) {
		/* Out of window: send ACK and drop. */
		//如果不是RST包，而且没有触发速率限制，则回ACK告诉发送方当前的窗口/状态，但不继续处理这个包
		if (!(flg & TCP_FLAG_RST) &&
		    !tcp_oow_rate_limited(sock_net(sk), skb,
					  LINUX_MIB_TCPACKSKIPPEDSYNRECV,
					  &tcp_rsk(req)->last_oow_ack_time))
			req->rsk_ops->send_ack(sk, skb, req);
		if (paws_reject)
			NET_INC_STATS(sock_net(sk), LINUX_MIB_PAWSESTABREJECTED);
		return NULL;
	}

	//如果数据包中带有时间戳且这个包的seq小于或等于rcv_nxt（即是旧包或当前应接收的包），就更新 req->ts_recent，为将来的PAWS检查提供参考
	if (tmp_opt.saw_tstamp && !after(TCP_SKB_CB(skb)->seq, tcp_rsk(req)->rcv_nxt))
		WRITE_ONCE(req->ts_recent, tmp_opt.rcv_tsval);
	//如果SYN重传且seq和原始初始序列号一致（rcv_isn），说明这个SYN已经处理过了，现在应该视为重复包，去掉SYN标志。
	if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn) {
		//裁剪SYN标志位，因为它已经在我们期望的接收窗口之外，从rcv_isn+1开始就不再期望SYN
		flg &= ~TCP_FLAG_SYN;
	}

	//当接收到一个带有RST或SYN标志的包时，在连接仍处于SYN-RECEIVED状态时，认为这是非法或异常的连接尝试，进行重置处理
	if (flg & (TCP_FLAG_RST|TCP_FLAG_SYN)) {
		TCP_INC_STATS(sock_net(sk), TCP_MIB_ATTEMPTFAILS);
		goto embryonic_reset;
	}

	//这里检查是否设置了ACK标志。如果没有设置（即不是一个带 ACK 的包），则直接丢弃该包（return NULL），不做进一步处理。
	if (!(flg & TCP_FLAG_ACK))
		return NULL;

	//如果TFO请求，那么不需要进一步处理这个包，直接返回已建立的子socket
	if (fastopen)
		return sk;

	/* 当启用了TCP_DEFER_ACCEPT（延迟接受）选项时，如果收到一个“裸的 ACK”（即没有数据，只是 ACK），就丢弃它 */
	if (req->num_timeout < inet_csk(sk)->icsk_accept_queue.rskq_defer_accept &&//表示这是一个还在延迟接受计数器允许范围内的请求
	    TCP_SKB_CB(skb)->end_seq == tcp_rsk(req)->rcv_isn + 1) {//表示客户端发来的 ACK 只是确认了最初 SYN+ACK 的应答，没有附带数据
		//标记这个请求已经被ACK过，这个标志在后续处理中可以用来判断连接是否被客户端确认过
		inet_rsk(req)->acked = 1;
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPDEFERACCEPTDROP);
		//丢弃这个 ACK 报文，不创建 socket，连接不进入 accept 队列。
	    //等待客户端重新发送带数据的报文，才会真正创建 socket 并传递给 accept()
		return NULL;
	}

	/* OK, ACK is valid, create big socket and feed this segment to it. It will repeat all the tests. THIS SEGMENT MUST MOVE SOCKET TOESTABLISHED STATE.
	 * If it will be dropped after socket is created, wait for troubles.
	 */
	child = inet_csk(sk)->icsk_af_ops->syn_recv_sock(sk, skb, req, NULL,
							 req, &own_req);//tcp_v4_syn_recv_sock
	if (!child)
		goto listen_overflow;
	//own_req 表示当前处理逻辑是否“拥有”该 request socket
	//rsk_drop_req是否应立即丢弃这个 req（可能是连接超时、被撤销等）
	if (own_req && rsk_drop_req(req)) {
		reqsk_queue_removed(&inet_csk(req->rsk_listener)->icsk_accept_queue, req);
		inet_csk_reqsk_queue_drop_and_put(req->rsk_listener, req);
		return child;
	}
	//保存接收到的skb中的 RPS（Receive Packet Steering）哈希。
	//这用于将接下来的数据包调度到对应CPU，提高多核并发处理能力。
	sock_rps_save_rxhash(child, skb);
	//基于握手 RTT（往返时延）计算，更新这个连接的 RTT 初值
	tcp_synack_rtt_meas(child, req);
	//如果当前逻辑是“偷”了别人处理的请求（例如 TFO 处理路径中这样可能发生），设置 *req_stolen = true，否则，标记为自己处理的请求
	*req_stolen = !own_req;
	//完成 hashdance 操作，hashdance 是一个术语，指将新的 socket 从临时连接状态（req）转换为完整连接，并插入到 established 哈希表中
	//此函数也负责设置 socket 状态为 ESTABLISHED，并通知上层应用该连接可用。
	return inet_csk_complete_hashdance(sk, child, req, own_req);

listen_overflow:
	//如果当前使用的 sk 不是监听 socket（可能是因为 TFO 创建了 child socket），记录一次“迁移失败”的统计信息
	if (sk != req->rsk_listener)
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMIGRATEREQFAILURE);
	//开关关闭：就不会对连接发RST，只标记 ACK 收到，然后“静默”丢弃这个请求。这样客户端会挂起，等待重试，而不是立即失败
	if (!READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_abort_on_overflow)) {
		inet_rsk(req)->acked = 1;
		return NULL;
	}

embryonic_reset:
	//如果不是一个RST报文（即不是客户端主动断开连接）
	if (!(flg & TCP_FLAG_RST)) {
		/* Received a bad SYN pkt - for TFO We try not to reset
		 * the local connection unless it's really necessary to
		 * avoid becoming vulnerable to outside attack aiming at
		 * resetting legit local connections.
		 */
		req->rsk_ops->send_reset(sk, skb);//主动向客户端发送一个 RST，表示连接已拒绝
	} else if (fastopen) { /* received a valid RST pkt */
		reqsk_fastopen_remove(sk, req, true);//清理 Fast Open 请求
		tcp_reset(sk, skb);
	}
	if (!fastopen) {
		//将请求从 listen 队列中删除
		bool unlinked = inet_csk_reqsk_queue_drop(sk, req);

		if (unlinked)
			__NET_INC_STATS(sock_net(sk), LINUX_MIB_EMBRYONICRSTS);
		//表示请求是否还留在队列中（比如刚刚已经被别人处理过）
		//unlinked为1表示删除了，说明请求已“被处理”或“被释放”了，告诉调用者“请求没被偷走”或“请求不再存在”
		//unlinked为0说明请求未被成功移除（可能被别人抢先处理）
		*req_stolen = !unlinked;
	}
	return NULL;
}
EXPORT_SYMBOL(tcp_check_req);

/*
 * Queue segment on the new socket if the new socket is active,
 * otherwise we just shortcircuit this and continue with
 * the new socket.
 *
 * For the vast majority of cases child->sk_state will be TCP_SYN_RECV
 * when entering. But other states are possible due to a race condition
 * where after __inet_lookup_established() fails but before the listener
 * locked is obtained, other packets cause the same connection to
 * be created.
 */

int tcp_child_process(struct sock *parent, struct sock *child,
		      struct sk_buff *skb)
	__releases(&((child)->sk_lock.slock))
{
	int ret = 0;
	int state = child->sk_state;

	/* record NAPI ID of child */
	sk_mark_napi_id(child, skb);
	//更新当前 socket 的统计信息
	tcp_segs_in(tcp_sk(child), skb);
	//child socket 当前没有被用户持有（未被应用层调用如 recv() 占用）
	if (!sock_owned_by_user(child)) {
		if (is_src_k2pro(skb))
			printk(KERN_INFO "%s: ->tcp_rcv_state_process\n", __func__);
		//处理接收的 TCP 包，改变状态机（如 SYN_RECV → ESTABLISHED），或者继续处理数据包。
		ret = tcp_rcv_state_process(child, skb);
		/* Wakeup parent, send SIGIO */
		//如果状态从 TCP_SYN_RECV 转变（说明握手完成），会：通知监听 socket（父socket）数据已准备好：可能触发select()/epoll()的返回或信号通知（如SIGIO）
		if (state == TCP_SYN_RECV && child->sk_state != state)
			parent->sk_data_ready(parent);
	} else {
		/* Alas, it is possible again, because we do lookup
		 * in main socket hash table and lock on listening
		 * socket does not protect us more.
		 * 说明 socket 被用户线程持有，暂时不能直接处理该 skb，把skb加入 socket 的 backlog 队列，由后续 release_sock() 时处理
		 */
		__sk_add_backlog(child, skb);
	}

	bh_unlock_sock(child);
	//递减 child 的引用计数（sock_put），可能触发回收
	sock_put(child);
	return ret;
}
EXPORT_SYMBOL(tcp_child_process);
