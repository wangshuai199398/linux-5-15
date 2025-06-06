// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * inet fragments management
 *
 * 		Authors:	Pavel Emelyanov <xemul@openvz.org>
 *				Started as consolidation of ipv4/ip_fragment.c,
 *				ipv6/reassembly. and ipv6 nf conntrack reassembly
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>

#include <net/sock.h>
#include <net/inet_frag.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include "../core/sock_destructor.h"

/* Use skb->cb to track consecutive/adjacent fragments coming at
 * the end of the queue. Nodes in the rb-tree queue will
 * contain "runs" of one or more adjacent fragments.
 *
 * Invariants:
 * - next_frag is NULL at the tail of a "run";
 * - the head of a "run" has the sum of all fragment lengths in frag_run_len.
 */
struct ipfrag_skb_cb {
	union {
		struct inet_skb_parm	h4;
		struct inet6_skb_parm	h6;
	};
	struct sk_buff		*next_frag;
	int			frag_run_len;
	int			ip_defrag_offset;
};

#define FRAG_CB(skb)		((struct ipfrag_skb_cb *)((skb)->cb))

static void fragcb_clear(struct sk_buff *skb)
{
	RB_CLEAR_NODE(&skb->rbnode);
	FRAG_CB(skb)->next_frag = NULL;
	FRAG_CB(skb)->frag_run_len = skb->len;
}

/* Append skb to the last "run". */
static void fragrun_append_to_last(struct inet_frag_queue *q,
				   struct sk_buff *skb)
{
	fragcb_clear(skb);

	FRAG_CB(q->last_run_head)->frag_run_len += skb->len;
	FRAG_CB(q->fragments_tail)->next_frag = skb;
	q->fragments_tail = skb;
}

/* Create a new "run" with the skb. */
static void fragrun_create(struct inet_frag_queue *q, struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct ipfrag_skb_cb) > sizeof(skb->cb));
	fragcb_clear(skb);

	if (q->last_run_head)
		rb_link_node(&skb->rbnode, &q->last_run_head->rbnode,
			     &q->last_run_head->rbnode.rb_right);
	else
		rb_link_node(&skb->rbnode, NULL, &q->rb_fragments.rb_node);
	rb_insert_color(&skb->rbnode, &q->rb_fragments);

	q->fragments_tail = skb;
	q->last_run_head = skb;
}

/* Given the OR values of all fragments, apply RFC 3168 5.3 requirements
 * Value : 0xff if frame should be dropped.
 *         0 or INET_ECN_CE value, to be ORed in to final iph->tos field
 */
const u8 ip_frag_ecn_table[16] = {
	/* at least one fragment had CE, and others ECT_0 or ECT_1 */
	[IPFRAG_ECN_CE | IPFRAG_ECN_ECT_0]			= INET_ECN_CE,
	[IPFRAG_ECN_CE | IPFRAG_ECN_ECT_1]			= INET_ECN_CE,
	[IPFRAG_ECN_CE | IPFRAG_ECN_ECT_0 | IPFRAG_ECN_ECT_1]	= INET_ECN_CE,

	/* invalid combinations : drop frame */
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_CE] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_ECT_0] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_ECT_1] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_ECT_0 | IPFRAG_ECN_ECT_1] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_CE | IPFRAG_ECN_ECT_0] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_CE | IPFRAG_ECN_ECT_1] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_CE | IPFRAG_ECN_ECT_0 | IPFRAG_ECN_ECT_1] = 0xff,
};
EXPORT_SYMBOL(ip_frag_ecn_table);

int inet_frags_init(struct inet_frags *f)
{
	f->frags_cachep = kmem_cache_create(f->frags_cache_name, f->qsize, 0, 0,
					    NULL);
	if (!f->frags_cachep)
		return -ENOMEM;

	refcount_set(&f->refcnt, 1);
	init_completion(&f->completion);
	return 0;
}
EXPORT_SYMBOL(inet_frags_init);

void inet_frags_fini(struct inet_frags *f)
{
	if (refcount_dec_and_test(&f->refcnt))
		complete(&f->completion);

	wait_for_completion(&f->completion);

	kmem_cache_destroy(f->frags_cachep);
	f->frags_cachep = NULL;
}
EXPORT_SYMBOL(inet_frags_fini);

/* called from rhashtable_free_and_destroy() at netns_frags dismantle */
static void inet_frags_free_cb(void *ptr, void *arg)
{
	struct inet_frag_queue *fq = ptr;
	int count;

	count = del_timer_sync(&fq->timer) ? 1 : 0;

	spin_lock_bh(&fq->lock);
	if (!(fq->flags & INET_FRAG_COMPLETE)) {
		fq->flags |= INET_FRAG_COMPLETE;
		count++;
	} else if (fq->flags & INET_FRAG_HASH_DEAD) {
		count++;
	}
	spin_unlock_bh(&fq->lock);

	if (refcount_sub_and_test(count, &fq->refcnt))
		inet_frag_destroy(fq);
}

static LLIST_HEAD(fqdir_free_list);

static void fqdir_free_fn(struct work_struct *work)
{
	struct llist_node *kill_list;
	struct fqdir *fqdir, *tmp;
	struct inet_frags *f;

	/* Atomically snapshot the list of fqdirs to free */
	kill_list = llist_del_all(&fqdir_free_list);

	/* We need to make sure all ongoing call_rcu(..., inet_frag_destroy_rcu)
	 * have completed, since they need to dereference fqdir.
	 * Would it not be nice to have kfree_rcu_barrier() ? :)
	 */
	rcu_barrier();

	llist_for_each_entry_safe(fqdir, tmp, kill_list, free_list) {
		f = fqdir->f;
		if (refcount_dec_and_test(&f->refcnt))
			complete(&f->completion);

		kfree(fqdir);
	}
}

static DECLARE_WORK(fqdir_free_work, fqdir_free_fn);

static void fqdir_work_fn(struct work_struct *work)
{
	struct fqdir *fqdir = container_of(work, struct fqdir, destroy_work);

	rhashtable_free_and_destroy(&fqdir->rhashtable, inet_frags_free_cb, NULL);

	if (llist_add(&fqdir->free_list, &fqdir_free_list))
		queue_work(system_wq, &fqdir_free_work);
}

int fqdir_init(struct fqdir **fqdirp, struct inet_frags *f, struct net *net)
{
	struct fqdir *fqdir = kzalloc(sizeof(*fqdir), GFP_KERNEL);
	int res;

	if (!fqdir)
		return -ENOMEM;
	fqdir->f = f;
	fqdir->net = net;
	res = rhashtable_init(&fqdir->rhashtable, &fqdir->f->rhash_params);
	if (res < 0) {
		kfree(fqdir);
		return res;
	}
	refcount_inc(&f->refcnt);
	*fqdirp = fqdir;
	return 0;
}
EXPORT_SYMBOL(fqdir_init);

static struct workqueue_struct *inet_frag_wq;

static int __init inet_frag_wq_init(void)
{
	inet_frag_wq = create_workqueue("inet_frag_wq");
	if (!inet_frag_wq)
		panic("Could not create inet frag workq");
	return 0;
}

pure_initcall(inet_frag_wq_init);

void fqdir_exit(struct fqdir *fqdir)
{
	INIT_WORK(&fqdir->destroy_work, fqdir_work_fn);
	queue_work(inet_frag_wq, &fqdir->destroy_work);
}
EXPORT_SYMBOL(fqdir_exit);

void inet_frag_kill(struct inet_frag_queue *fq)
{
	if (del_timer(&fq->timer))
		refcount_dec(&fq->refcnt);

	if (!(fq->flags & INET_FRAG_COMPLETE)) {
		struct fqdir *fqdir = fq->fqdir;

		fq->flags |= INET_FRAG_COMPLETE;
		rcu_read_lock();
		/* The RCU read lock provides a memory barrier
		 * guaranteeing that if fqdir->dead is false then
		 * the hash table destruction will not start until
		 * after we unlock.  Paired with fqdir_pre_exit().
		 */
		if (!READ_ONCE(fqdir->dead)) {
			rhashtable_remove_fast(&fqdir->rhashtable, &fq->node,
					       fqdir->f->rhash_params);
			refcount_dec(&fq->refcnt);
		} else {
			fq->flags |= INET_FRAG_HASH_DEAD;
		}
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL(inet_frag_kill);

static void inet_frag_destroy_rcu(struct rcu_head *head)
{
	struct inet_frag_queue *q = container_of(head, struct inet_frag_queue,
						 rcu);
	struct inet_frags *f = q->fqdir->f;

	if (f->destructor)
		f->destructor(q);
	kmem_cache_free(f->frags_cachep, q);
}

unsigned int inet_frag_rbtree_purge(struct rb_root *root)
{
	struct rb_node *p = rb_first(root);
	unsigned int sum = 0;

	while (p) {
		struct sk_buff *skb = rb_entry(p, struct sk_buff, rbnode);

		p = rb_next(p);
		rb_erase(&skb->rbnode, root);
		while (skb) {
			struct sk_buff *next = FRAG_CB(skb)->next_frag;

			sum += skb->truesize;
			kfree_skb(skb);
			skb = next;
		}
	}
	return sum;
}
EXPORT_SYMBOL(inet_frag_rbtree_purge);

void inet_frag_destroy(struct inet_frag_queue *q)
{
	struct fqdir *fqdir;
	unsigned int sum, sum_truesize = 0;
	struct inet_frags *f;

	WARN_ON(!(q->flags & INET_FRAG_COMPLETE));
	WARN_ON(del_timer(&q->timer) != 0);

	/* Release all fragment data. */
	fqdir = q->fqdir;
	f = fqdir->f;
	sum_truesize = inet_frag_rbtree_purge(&q->rb_fragments);
	sum = sum_truesize + f->qsize;

	call_rcu(&q->rcu, inet_frag_destroy_rcu);

	sub_frag_mem_limit(fqdir, sum);
}
EXPORT_SYMBOL(inet_frag_destroy);

static struct inet_frag_queue *inet_frag_alloc(struct fqdir *fqdir,
					       struct inet_frags *f,
					       void *arg)
{
	struct inet_frag_queue *q;

	q = kmem_cache_zalloc(f->frags_cachep, GFP_ATOMIC);
	if (!q)
		return NULL;

	q->fqdir = fqdir;
	f->constructor(q, arg);
	add_frag_mem_limit(fqdir, f->qsize);

	timer_setup(&q->timer, f->frag_expire, 0);
	spin_lock_init(&q->lock);
	refcount_set(&q->refcnt, 3);

	return q;
}

static struct inet_frag_queue *inet_frag_create(struct fqdir *fqdir,
						void *arg,
						struct inet_frag_queue **prev)
{
	struct inet_frags *f = fqdir->f;
	struct inet_frag_queue *q;

	q = inet_frag_alloc(fqdir, f, arg);
	if (!q) {
		*prev = ERR_PTR(-ENOMEM);
		return NULL;
	}
	mod_timer(&q->timer, jiffies + fqdir->timeout);

	*prev = rhashtable_lookup_get_insert_key(&fqdir->rhashtable, &q->key,
						 &q->node, f->rhash_params);
	if (*prev) {
		q->flags |= INET_FRAG_COMPLETE;
		inet_frag_kill(q);
		inet_frag_destroy(q);
		return NULL;
	}
	return q;
}

/* TODO : call from rcu_read_lock() and no longer use refcount_inc_not_zero() */
struct inet_frag_queue *inet_frag_find(struct fqdir *fqdir, void *key)
{
	/* This pairs with WRITE_ONCE() in fqdir_pre_exit(). */
	long high_thresh = READ_ONCE(fqdir->high_thresh);
	struct inet_frag_queue *fq = NULL, *prev;

	if (!high_thresh || frag_mem_limit(fqdir) > high_thresh)
		return NULL;

	rcu_read_lock();

	prev = rhashtable_lookup(&fqdir->rhashtable, key, fqdir->f->rhash_params);
	if (!prev)
		fq = inet_frag_create(fqdir, key, &prev);
	if (!IS_ERR_OR_NULL(prev)) {
		fq = prev;
		if (!refcount_inc_not_zero(&fq->refcnt))
			fq = NULL;
	}
	rcu_read_unlock();
	return fq;
}
EXPORT_SYMBOL(inet_frag_find);

/*将新的分片 skb 插入到当前分片队列中（基于 offset 的位置）
  •这段代码实质是在红黑树中定位分片的正确插入位置（基于分片偏移排序）；
  •保证分片在链中无重叠且有序；
  •重叠分片直接返回错误导致丢弃整个分片重组队列，保证安全性；
  •重复分片直接忽略；
  •最终把新的 skb 插入红黑树，便于快速查询和重组
  为什么要用红黑树: 主要是为了实现高效、可维护的IP分片查找与插入算法
*/
int inet_frag_queue_insert(struct inet_frag_queue *q, struct sk_buff *skb,
			   int offset, int end)
{
	struct sk_buff *last = q->fragments_tail;

	/* RFC5722, Section 4, amended by Errata ID : 3089
	 *                          When reassembling an IPv6 datagram, if
	 *   one or more its constituent fragments is determined to be an
	 *   overlapping fragment, the entire datagram (and any constituent
	 *   fragments) MUST be silently discarded.
	 *
	 * Duplicates, however, should be ignored (i.e. skb dropped, but the
	 * queue/fragments kept for later reassembly).
	 */
	//没有last说明是第一个分片
	if (!last)
		fragrun_create(q, skb);  /* First fragment. */
	else if (FRAG_CB(last)->ip_defrag_offset + last->len < end) {//新分片在“最后一个”后面
		/* This is the common case: skb goes to the end. */
		/* Detect and discard overlaps. */
		//检查是否“部分重叠”, 一律丢弃整个包
		if (offset < FRAG_CB(last)->ip_defrag_offset + last->len)
			return IPFRAG_OVERLAP;
		//紧接着上一个，直接追加
		if (offset == FRAG_CB(last)->ip_defrag_offset + last->len)
			fragrun_append_to_last(q, skb);
		else
			fragrun_create(q, skb);//有间隙，新建 fragment run
	} else {
		/* Binary search. Note that skb can become the first fragment,
		 * but not the last (covered above).
		 */
		struct rb_node **rbn, *parent;
		//rbn 指向红黑树的根节点指针
		rbn = &q->rb_fragments.rb_node;
		do {
			struct sk_buff *curr;
			int curr_run_end;

			parent = *rbn;
			curr = rb_to_skb(parent);//由 rb_node 获取 sk_buff 指针
			curr_run_end = FRAG_CB(curr)->ip_defrag_offset +
					FRAG_CB(curr)->frag_run_len;//当前分片在队列中的“结束偏移”，即起始偏移 + 当前分片长度（包含连续的碎片长度）
			if (end <= FRAG_CB(curr)->ip_defrag_offset)//如果新分片结束位置end不超过当前分片起始偏移，说明应该插入到当前节点左边
				rbn = &parent->rb_left;
			else if (offset >= curr_run_end)//如果新分片起始偏移offset在当前分片范围右侧之后，则向右子树继续查找
				rbn = &parent->rb_right;
			else if (offset >= FRAG_CB(curr)->ip_defrag_offset &&
				 end <= curr_run_end)//如果新分片完全包含于当前已有分片的范围内，则为重复分片，忽略这次插入
				return IPFRAG_DUP;
			else
				return IPFRAG_OVERLAP;//如果两者有重叠但不完全包含，说明报文异常，需丢弃整个IP分片重组队列
		} while (*rbn);
		/* Here we have parent properly set, and rbn pointing to
		 * one of its NULL left/right children. Insert skb.
		 */
		//parent 是新节点的父节点指针，rbn 是父节点某个子指针的地址(左或右)，当前为 NULL
		fragcb_clear(skb);//清理 skb 上的 frag control block
		rb_link_node(&skb->rbnode, parent, rbn);//找到合适位置后，将新节点连接到父节点的左或右指针
		rb_insert_color(&skb->rbnode, &q->rb_fragments);//插入并修正红黑树平衡
	}
	//保存这个分片的偏移量，用于后续拼接
	FRAG_CB(skb)->ip_defrag_offset = offset;

	return IPFRAG_OK;
}
EXPORT_SYMBOL(inet_frag_queue_insert);

//将 IP 分片队列中所有 skb 排好序的片段准备串联起来，并处理 skb 的内存、引用、结构等，使其可用作完整包的载体
void *inet_frag_reasm_prepare(struct inet_frag_queue *q, struct sk_buff *skb,
			      struct sk_buff *parent)
{
	struct sk_buff *fp, *head = skb_rb_first(&q->rb_fragments);
	void (*destructor)(struct sk_buff *);
	unsigned int orig_truesize = 0;
	struct sk_buff **nextp = NULL;
	struct sock *sk = skb->sk;
	int delta;

	if (sk && is_skb_wmem(skb)) {
		/* TX: skb->sk might have been passed as argument to
		 * dst->output and must remain valid until tx completes.
		 *
		 * Move sk to reassembled skb and fix up wmem accounting.
		 */
		orig_truesize = skb->truesize;
		destructor = skb->destructor;
	}

	if (head != skb) {
		fp = skb_clone(skb, GFP_ATOMIC);
		if (!fp) {
			head = skb;
			goto out_restore_sk;
		}
		FRAG_CB(fp)->next_frag = FRAG_CB(skb)->next_frag;
		if (RB_EMPTY_NODE(&skb->rbnode))
			FRAG_CB(parent)->next_frag = fp;
		else
			rb_replace_node(&skb->rbnode, &fp->rbnode,
					&q->rb_fragments);
		if (q->fragments_tail == skb)
			q->fragments_tail = fp;

		if (orig_truesize) {
			/* prevent skb_morph from releasing sk */
			skb->sk = NULL;
			skb->destructor = NULL;
		}
		//利用 skb_morph() 直接将旧头部结构迁移给当前 skb，保证我们拼接的主 skb 是最新到达的分片（可优化 cache locality）
		skb_morph(skb, head);
		FRAG_CB(skb)->next_frag = FRAG_CB(head)->next_frag;
		rb_replace_node(&head->rbnode, &skb->rbnode,
				&q->rb_fragments);
		consume_skb(head);
		head = skb;
	}
	WARN_ON(FRAG_CB(head)->ip_defrag_offset != 0);

	delta = -head->truesize;

	/* Head of list must not be cloned. */
	if (skb_unclone(head, GFP_ATOMIC))
		goto out_restore_sk;

	delta += head->truesize;
	if (delta)
		add_frag_mem_limit(q->fqdir, delta);

	/* If the first fragment is fragmented itself, we split
	 * it to two chunks: the first with data and paged part
	 * and the second, holding only fragments.
	 */
	if (skb_has_frag_list(head)) {
		struct sk_buff *clone;
		int i, plen = 0;

		clone = alloc_skb(0, GFP_ATOMIC);
		if (!clone)
			goto out_restore_sk;
		skb_shinfo(clone)->frag_list = skb_shinfo(head)->frag_list;
		skb_frag_list_init(head);
		for (i = 0; i < skb_shinfo(head)->nr_frags; i++)
			plen += skb_frag_size(&skb_shinfo(head)->frags[i]);
		clone->data_len = head->data_len - plen;
		clone->len = clone->data_len;
		head->truesize += clone->truesize;
		clone->csum = 0;
		clone->ip_summed = head->ip_summed;
		add_frag_mem_limit(q->fqdir, clone->truesize);
		skb_shinfo(head)->frag_list = clone;
		nextp = &clone->next;
	} else {
		nextp = &skb_shinfo(head)->frag_list;
	}

out_restore_sk:
	if (orig_truesize) {
		int ts_delta = head->truesize - orig_truesize;

		/* if this reassembled skb is fragmented later,
		 * fraglist skbs will get skb->sk assigned from head->sk,
		 * and each frag skb will be released via sock_wfree.
		 *
		 * Update sk_wmem_alloc.
		 */
		head->sk = sk;
		head->destructor = destructor;
		refcount_add(ts_delta, &sk->sk_wmem_alloc);
	}

	return nextp;
}
EXPORT_SYMBOL(inet_frag_reasm_prepare);

/*将所有接收到的 IP 分片拼接成一个完整的 skb 包，并完成必要的内存/引用计数修正
	•	从红黑树中按顺序遍历所有分片；
	•	依次拼接到重组的 skb 上；
	•	处理校验和、内存统计、frag_list 等数据结构；
	•	清理红黑树节点。
try_coalesce：是否尝试直接合并 skb 数据以减少内存使用（通过 skb_try_coalesce）
*/
void inet_frag_reasm_finish(struct inet_frag_queue *q, struct sk_buff *head,
			    void *reasm_data, bool try_coalesce)
{
	struct sock *sk = is_skb_wmem(head) ? head->sk : NULL;
	const unsigned int head_truesize = head->truesize;
	struct sk_buff **nextp = (struct sk_buff **)reasm_data;
	struct rb_node *rbn;
	struct sk_buff *fp;
	int sum_truesize;

	skb_push(head, head->data - skb_network_header(head));

	/* Traverse the tree in order, to build frag_list. */
	fp = FRAG_CB(head)->next_frag;
	rbn = rb_next(&head->rbnode);
	rb_erase(&head->rbnode, &q->rb_fragments);

	sum_truesize = head->truesize;
	while (rbn || fp) {
		/* fp points to the next sk_buff in the current run;
		 * rbn points to the next run.
		 */
		/* Go through the current run. */
		while (fp) {
			struct sk_buff *next_frag = FRAG_CB(fp)->next_frag;
			bool stolen;
			int delta;

			sum_truesize += fp->truesize;
			if (head->ip_summed != fp->ip_summed)
				head->ip_summed = CHECKSUM_NONE;
			else if (head->ip_summed == CHECKSUM_COMPLETE)
				head->csum = csum_add(head->csum, fp->csum);

			if (try_coalesce && skb_try_coalesce(head, fp, &stolen,
							     &delta)) {
				kfree_skb_partial(fp, stolen);
			} else {
				fp->prev = NULL;
				memset(&fp->rbnode, 0, sizeof(fp->rbnode));
				fp->sk = NULL;

				head->data_len += fp->len;
				head->len += fp->len;
				head->truesize += fp->truesize;

				*nextp = fp;
				nextp = &fp->next;
			}

			fp = next_frag;
		}
		/* Move to the next run. */
		if (rbn) {
			struct rb_node *rbnext = rb_next(rbn);

			fp = rb_to_skb(rbn);
			rb_erase(rbn, &q->rb_fragments);
			rbn = rbnext;
		}
	}
	sub_frag_mem_limit(q->fqdir, sum_truesize);

	*nextp = NULL;
	skb_mark_not_on_list(head);
	head->prev = NULL;
	head->tstamp = q->stamp;

	if (sk)
		refcount_add(sum_truesize - head_truesize, &sk->sk_wmem_alloc);
}
EXPORT_SYMBOL(inet_frag_reasm_finish);

struct sk_buff *inet_frag_pull_head(struct inet_frag_queue *q)
{
	struct sk_buff *head, *skb;

	head = skb_rb_first(&q->rb_fragments);
	if (!head)
		return NULL;
	skb = FRAG_CB(head)->next_frag;
	if (skb)
		rb_replace_node(&head->rbnode, &skb->rbnode,
				&q->rb_fragments);
	else
		rb_erase(&head->rbnode, &q->rb_fragments);
	memset(&head->rbnode, 0, sizeof(head->rbnode));
	barrier();

	if (head == q->fragments_tail)
		q->fragments_tail = NULL;

	sub_frag_mem_limit(q->fqdir, head->truesize);

	return head;
}
EXPORT_SYMBOL(inet_frag_pull_head);
