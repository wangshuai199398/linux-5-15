// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Queued spinlock
 *
 * (C) Copyright 2013-2015 Hewlett-Packard Development Company, L.P.
 * (C) Copyright 2013-2014,2018 Red Hat, Inc.
 * (C) Copyright 2015 Intel Corp.
 * (C) Copyright 2015 Hewlett-Packard Enterprise Development LP
 *
 * Authors: Waiman Long <longman@redhat.com>
 *          Peter Zijlstra <peterz@infradead.org>
 */

#ifndef _GEN_PV_LOCK_SLOWPATH

#include <linux/smp.h>
#include <linux/bug.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/mutex.h>
#include <linux/prefetch.h>
#include <asm/byteorder.h>
#include <asm/qspinlock.h>

/*
 * Include queued spinlock statistics code
 */
#include "qspinlock_stat.h"

/*
 * The basic principle of a queue-based spinlock can best be understood
 * by studying a classic queue-based spinlock implementation called the
 * MCS lock. A copy of the original MCS lock paper ("Algorithms for Scalable
 * Synchronization on Shared-Memory Multiprocessors by Mellor-Crummey and
 * Scott") is available at
 *
 * https://bugzilla.kernel.org/show_bug.cgi?id=206115
 *
 * This queued spinlock implementation is based on the MCS lock, however to
 * make it fit the 4 bytes we assume spinlock_t to be, and preserve its
 * existing API, we must modify it somehow.
 *
 * In particular; where the traditional MCS lock consists of a tail pointer
 * (8 bytes) and needs the next pointer (another 8 bytes) of its own node to
 * unlock the next pending (next->locked), we compress both these: {tail,
 * next->locked} into a single u32 value.
 *
 * Since a spinlock disables recursion of its own context and there is a limit
 * to the contexts that can nest; namely: task, softirq, hardirq, nmi. As there
 * are at most 4 nesting levels, it can be encoded by a 2-bit number. Now
 * we can encode the tail by combining the 2-bit nesting level with the cpu
 * number. With one byte for the lock value and 3 bytes for the tail, only a
 * 32-bit word is now needed. Even though we only need 1 bit for the lock,
 * we extend it to a full byte to achieve better performance for architectures
 * that support atomic byte write.
 *
 * We also change the first spinner to spin on the lock bit instead of its
 * node; whereby avoiding the need to carry a node from lock to unlock, and
 * preserving existing lock API. This also makes the unlock code simpler and
 * faster.
 *
 * N.B. The current implementation only supports architectures that allow
 *      atomic operations on smaller 8-bit and 16-bit data types.
 *
 */

#include "mcs_spinlock.h"
#define MAX_NODES	4

/*
 * On 64-bit architectures, the mcs_spinlock structure will be 16 bytes in
 * size and four of them will fit nicely in one 64-byte cacheline. For
 * pvqspinlock, however, we need more space for extra data. To accommodate
 * that, we insert two more long words to pad it up to 32 bytes. IOW, only
 * two of them can fit in a cacheline in this case. That is OK as it is rare
 * to have more than 2 levels of slowpath nesting in actual use. We don't
 * want to penalize pvqspinlocks to optimize for a rare case in native
 * qspinlocks.
 */
struct qnode {
	struct mcs_spinlock mcs;
#ifdef CONFIG_PARAVIRT_SPINLOCKS
	long reserved[2];
#endif
};

/*
 * The pending bit spinning loop count.
 * This heuristic is used to limit the number of lockword accesses
 * made by atomic_cond_read_relaxed when waiting for the lock to
 * transition out of the "== _Q_PENDING_VAL" state. We don't spin
 * indefinitely because there's no guarantee that we'll make forward
 * progress.
 */
#ifndef _Q_PENDING_LOOPS
#define _Q_PENDING_LOOPS	1
#endif

/*
 * Per-CPU queue node structures; we can never have more than 4 nested
 * contexts: task, softirq, hardirq, nmi.
 *
 * Exactly fits one 64-byte cacheline on a 64-bit architecture.
 *
 * PV doubles the storage and uses the second cacheline for PV state.
 */
static DEFINE_PER_CPU_ALIGNED(struct qnode, qnodes[MAX_NODES]);

/*
 * We must be able to distinguish between no-tail and the tail at 0:0,
 * therefore increment the cpu number by one.
 */

static inline __pure u32 encode_tail(int cpu, int idx)
{
	u32 tail;

	tail  = (cpu + 1) << _Q_TAIL_CPU_OFFSET;
	tail |= idx << _Q_TAIL_IDX_OFFSET; /* assume < 4 */

	return tail;
}

static inline __pure struct mcs_spinlock *decode_tail(u32 tail)
{
	int cpu = (tail >> _Q_TAIL_CPU_OFFSET) - 1;
	int idx = (tail &  _Q_TAIL_IDX_MASK) >> _Q_TAIL_IDX_OFFSET;

	return per_cpu_ptr(&qnodes[idx].mcs, cpu);
}

static inline __pure
struct mcs_spinlock *grab_mcs_node(struct mcs_spinlock *base, int idx)
{
	return &((struct qnode *)base + idx)->mcs;
}

#define _Q_LOCKED_PENDING_MASK (_Q_LOCKED_MASK | _Q_PENDING_MASK)

#if _Q_PENDING_BITS == 8
/**
 * clear_pending - clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,* -> *,0,*
 */
static __always_inline void clear_pending(struct qspinlock *lock)
{
	WRITE_ONCE(lock->pending, 0);
}

/**
 * clear_pending_set_locked - take ownership and clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,0 -> *,0,1
 *
 * Lock stealing is not allowed if this function is used.
 */
static __always_inline void clear_pending_set_locked(struct qspinlock *lock)
{
	WRITE_ONCE(lock->locked_pending, _Q_LOCKED_VAL);
}

/*
 * xchg_tail - Put in the new queue tail code word & retrieve previous one
 * @lock : Pointer to queued spinlock structure
 * @tail : The new queue tail code word
 * Return: The previous queue tail code word
 *
 * xchg(lock, tail), which heads an address dependency
 *
 * p,*,* -> n,*,* ; prev = xchg(lock, node)
 */
static __always_inline u32 xchg_tail(struct qspinlock *lock, u32 tail)
{
	/*
	 * We can use relaxed semantics since the caller ensures that the
	 * MCS node is properly initialized before updating the tail.
	 */
	return (u32)xchg_relaxed(&lock->tail,
				 tail >> _Q_TAIL_OFFSET) << _Q_TAIL_OFFSET;
}

#else /* _Q_PENDING_BITS == 8 */

/**
 * clear_pending - clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,* -> *,0,*
 */
static __always_inline void clear_pending(struct qspinlock *lock)
{
	atomic_andnot(_Q_PENDING_VAL, &lock->val);
}

/**
 * clear_pending_set_locked - take ownership and clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,0 -> *,0,1
 */
static __always_inline void clear_pending_set_locked(struct qspinlock *lock)
{
	atomic_add(-_Q_PENDING_VAL + _Q_LOCKED_VAL, &lock->val);
}

/**
 * xchg_tail - Put in the new queue tail code word & retrieve previous one
 * @lock : Pointer to queued spinlock structure
 * @tail : The new queue tail code word
 * Return: The previous queue tail code word
 *
 * xchg(lock, tail)
 *
 * p,*,* -> n,*,* ; prev = xchg(lock, node)
 */
static __always_inline u32 xchg_tail(struct qspinlock *lock, u32 tail)
{
	u32 old, new, val = atomic_read(&lock->val);

	for (;;) {
		new = (val & _Q_LOCKED_PENDING_MASK) | tail;
		/*
		 * We can use relaxed semantics since the caller ensures that
		 * the MCS node is properly initialized before updating the
		 * tail.
		 */
		old = atomic_cmpxchg_relaxed(&lock->val, val, new);
		if (old == val)
			break;

		val = old;
	}
	return old;
}
#endif /* _Q_PENDING_BITS == 8 */

/**
 * queued_fetch_set_pending_acquire - fetch the whole lock value and set pending
 * @lock : Pointer to queued spinlock structure
 * Return: The previous lock value
 *
 * *,*,* -> *,1,*
 */
#ifndef queued_fetch_set_pending_acquire
static __always_inline u32 queued_fetch_set_pending_acquire(struct qspinlock *lock)
{
	return atomic_fetch_or_acquire(_Q_PENDING_VAL, &lock->val);
}
#endif

/**
 * set_locked - Set the lock bit and own the lock
 * @lock: Pointer to queued spinlock structure
 *
 * *,*,0 -> *,0,1
 */
static __always_inline void set_locked(struct qspinlock *lock)
{
	WRITE_ONCE(lock->locked, _Q_LOCKED_VAL);
}


/*
 * Generate the native code for queued_spin_unlock_slowpath(); provide NOPs for
 * all the PV callbacks.
 */

static __always_inline void __pv_init_node(struct mcs_spinlock *node) { }
static __always_inline void __pv_wait_node(struct mcs_spinlock *node,
					   struct mcs_spinlock *prev) { }
static __always_inline void __pv_kick_node(struct qspinlock *lock,
					   struct mcs_spinlock *node) { }
static __always_inline u32  __pv_wait_head_or_lock(struct qspinlock *lock,
						   struct mcs_spinlock *node)
						   { return 0; }

#define pv_enabled()		false

#define pv_init_node		__pv_init_node
#define pv_wait_node		__pv_wait_node
#define pv_kick_node		__pv_kick_node
#define pv_wait_head_or_lock	__pv_wait_head_or_lock

#ifdef CONFIG_PARAVIRT_SPINLOCKS
#define queued_spin_lock_slowpath	native_queued_spin_lock_slowpath
#endif

#endif /* _GEN_PV_LOCK_SLOWPATH */

/**
 * queued_spin_lock_slowpath - acquire the queued spinlock
 * @lock: Pointer to queued spinlock structure
 * @val: Current value of the queued spinlock 32-bit word
 *
 * (queue tail, pending bit, lock value)
 *
 *              fast     :    slow                                  :    unlock
 *                       :                                          :
 * uncontended  (0,0,0) -:--> (0,0,1) ------------------------------:--> (*,*,0)
 *                       :       | ^--------.------.             /  :
 *                       :       v           \      \            |  :
 * pending               :    (0,1,1) +--> (0,1,0)   \           |  :
 *                       :       | ^--'              |           |  :
 *                       :       v                   |           |  :
 * uncontended           :    (n,x,y) +--> (n,0,0) --'           |  :
 *   queue               :       | ^--'                          |  :
 *                       :       v                               |  :
 * contended             :    (*,x,y) +--> (*,0,0) ---> (*,0,1) -'  :
 *   queue               :         ^--'                             :
 * 
 * 当 val 指示当前锁已被占用时，该函数会：
 *   1.	先尝试乐观地加锁（设置 pending 位）
 *   2.	若失败，则进入慢路径，使用 MCS 锁排队
 *   3.	直到获取锁后退出，完成加锁操作
 */
void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
{
	struct mcs_spinlock *prev, *next, *node;
	u32 old, tail;
	int idx;

	BUILD_BUG_ON(CONFIG_NR_CPUS >= (1U << _Q_TAIL_CPU_BITS));
	// 若启用了 paravirtualization（PV，用于虚拟机优化），跳转到 PV 特殊路径
	if (pv_enabled())
		goto pv_queue;
	// 若 virt_spin_lock() 成功抢锁，直接返回
	if (virt_spin_lock(lock))
		return;

	/*
	 * 如果当前状态是 PENDING，说明别的线程正在等待锁转交
	 * 当前线程短暂自旋，等待 pending → locked 的交接完成，避免过早入队（提高性能）
	 * 0,1,0 -> 0,0,1
	 */
	if (val == _Q_PENDING_VAL) {
		int cnt = _Q_PENDING_LOOPS;
		val = atomic_cond_read_relaxed(&lock->val,
					       (VAL != _Q_PENDING_VAL) || !cnt--);
	}

	/*
	 * 如果我们检测到任何争用，就排队
	 */
	if (val & ~_Q_LOCKED_MASK)
		goto queue;

	/* 再尝试设置 PENDING 位
	 * 表示“我准备抢锁”，设置 PENDING 标志
	 * 如果此时没有人竞争锁，并能成功获取，则锁住并返回
	 * 0,0,* -> 0,1,* -> 0,0,1 pending, trylock
	 */
	val = queued_fetch_set_pending_acquire(lock);

	/* 检测锁竞争 → 入队排队
	 * 如果锁值中包含 TAIL（有人排队）或 PENDING（其他线程也在抢锁），说明竞争激烈 → 排队
	 *
	 * 我们需要撤销当前操作并加入等待队列；因为我们设置 PENDING 标志的操作可能导致原本的 n,0,0 → 0,0,0 状态转换失败，现在那个线程可能正在等待 @next 变为非 NULL
	 */
	if (unlikely(val & ~_Q_LOCKED_MASK)) {

		/* Undo PENDING if we set it. */
		if (!(val & _Q_PENDING_MASK))
			clear_pending(lock);

		goto queue;
	}

	/*
	 * 我们当前处于 PENDING 状态，需等待当前锁拥有者释放锁，然后自己抢占锁
	 *
	 * 状态转换：0,1,1 -> 0,1,0（表示清除 PENDING 标志）
	 *
	 * 这个等待循环必须使用load-acquire，以配合释放锁时的store-release，从而建立锁的顺序一致性；这是因为并非所有 clear_pending_set_locked 的实现都隐含完整的内存屏障
	 */
	if (val & _Q_LOCKED_MASK)
		atomic_cond_read_acquire(&lock->val, !(VAL & _Q_LOCKED_MASK));

	/*
	 * 获取所有权并清除 PENDING 位
	 *
	 * 0,1,0 -> 0,0,1
	 */
	clear_pending_set_locked(lock);
	lockevent_inc(lock_pending);
	return;

	/*
	 * PENDING 位的乐观自旋结束，MCS 排队开始，进入排队路径（MCS 队列锁）
	 */
queue:
	lockevent_inc(lock_slowpath);
pv_queue:
	//获取当前 CPU 对应的 MCS 锁节点，构造链表的节点（MCS 样式），用于链式等待锁
	node = this_cpu_ptr(&qnodes[0].mcs);
	//从当前 CPU 的 qnode 结构中取出当前嵌套层索引（count），然后自增
	idx = node->count++;
	//生成一个 32 位整数（tail 值），编码当前 CPU 的 ID 和它的嵌套层次（idx）
	tail = encode_tail(smp_processor_id(), idx);

	/*
	 * 分配了 4 个节点，是基于“不会在嵌套的 NMI（不可屏蔽中断）中获取自旋锁”的假设
	 * 但在某些架构上，这个假设可能不成立，尽管实际中需要超过 4 个节点的情况极其罕见
	 * 当确实发生这种情况时，我们会回退到直接在锁上自旋，而不使用任何 MCS 节点
	 * 构建一个本地 MCS 节点（MCS 风格），挂入锁的等待链表中。每个 CPU 通常有一组预分配的 qnodes，用于避免动态内存分配
	 */
	if (unlikely(idx >= MAX_NODES)) {
		lockevent_inc(lock_no_node);
		while (!queued_spin_trylock(lock))
			cpu_relax();
		goto release;
	}

	node = grab_mcs_node(node, idx);

	/*
	 * 统计非零索引值的数量
	 */
	lockevent_cond_inc(lock_use_node2 + idx - 1, idx);

	/*
	 * 确保我们在初始化实际节点之前，先递增 head 节点的 count 字段
	 * 如果编译器“好心”地重新排序了这些写操作（store），那么中断（IRQ）可能会覆盖我们正在赋的值
	 */
	barrier();

	node->locked = 0;
	node->next = NULL;
	pv_init_node(node);

	/*
	 * 我们访问了每个 CPU 的队列节点中的一个（可能是）冷缓存行
	 * 再次尝试一次 trylock，希望在我们“没注意”的这段时间里，有其他线程释放了锁
	 * 尝试再次获取锁
	 */
	if (queued_spin_trylock(lock))
		goto release;

	/*
	 * 确保在通过 xchg_tail 更新 tail 并可能通过 WRITE_ONCE(prev->next, node) 将 @node 链接到等待队列之前，@node 的初始化已经完成
	 */
	smp_wmb();

	/* 构建 MCS 队列并等待获取锁
	 * 发布更新后的 tail（队尾）
	 * 我们已经访问过排队相关的缓存行，因此无需再处理 PENDING 状态的事情
	 *
	 * p,*,* -> n,*,*
	 * 更新队列的尾部，通过 xchg_tail() 原子更新锁的尾部，返回旧尾部用于构造链
	 */
	old = xchg_tail(lock, tail);
	next = NULL;

	/* 
	 * 如果存在前一个节点：将其连接上，并等待直到自己成为等待队列的头部
	 * 检索原先的尾部
	 */
	if (old & _Q_TAIL_MASK) {
		// 说明已有线程排队 → 链接前驱
		prev = decode_tail(old);

		/* Link @node into the waitqueue. */
		WRITE_ONCE(prev->next, node);

		pv_wait_node(node, prev);
		// 自旋等待
		arch_mcs_spin_lock_contended(&node->locked);

		/*
		 * 在等待 MCS 锁期间，next 指针可能已经被其他等待锁的线程设置
		 * 我们会“乐观地”加载这个 next 指针，并预取它所在的缓存行用于写入，以减少即将到来的 MCS 解锁操作的延迟
		 */
		next = READ_ONCE(node->next);
		if (next)
			prefetchw(next);
	}

	/* 等待持锁者释放锁（成为队头）
	 * 我们现在处于等待队列的队头，需等待锁的拥有者和 PENDING 状态都清除
	 *
	 * 状态变化：*,x,y → *,0,0（只关心 locked 和 pending 位的变化）
	 *
	 * 这个等待循环必须使用带有 acquire 语义的加载操作，以配合释放锁时的 store-release，从而建立锁的顺序一致性；
	 * 这是因为下面的 set_locked() 函数并不隐含完整的内存屏障
	 *
	 * 如果启用了 PV（paravirtual 虚拟化）机制，pv_wait_head_or_lock 函数会尝试获取锁，并返回非零值，表示已成功获取锁。
	 * 这时我们必须跳过 atomic_cond_read_acquire() 的调用
	 *
	 * 由于新的 PV 队列头尚未被指定，锁的值不会变成 _Q_SLOW_VAL，所以 set_locked() 和 atomic_cmpxchg_relaxed() 的调用都是安全的
	 * 
	 * 如果 PV 没有启用，则该函数返回 0
	 *
	 */
	if ((val = pv_wait_head_or_lock(lock, node)))
		goto locked;
	// 等成为队头后，再等待锁变空，再去尝试 set_locked()
	val = atomic_cond_read_acquire(&lock->val, !(VAL & _Q_LOCKED_PENDING_MASK));

locked:
	/*
	 * 尝试获取锁：设置锁位（真正持有锁）
	 *
	 * n,0,0 → 0,0,1: 表示无竞争地加锁（uncontended）
	 * *,*,0 -> *,*,1: 表示在有竞争的情况下加锁（contended）
	 *
	 * 如果队列头是队列中的唯一元素（即锁的值等于 tail），并且没有线程处于 pending 状态，那么我们可以清除 tail 字段并直接获取锁。
	 * 否则，我们只需要设置锁位即可（不管 tail）
	 */

	/*
	 * 在启用 Paravirtualization（PV）机制的情况下，可能由于锁被“偷走”（lock stealing），我们已经设置了 _Q_LOCKED_VAL，因此还必须允许以下状态转换：
	 *
	 * n,0,1 -> 0,0,1: 允许在已加锁但没有其他线程 pending 的情况下继续加锁
	 *
	 * 注意：此时 (val & _Q_PENDING_MASK) == 0，因为之前的等待逻辑已经确保了 PENDING 位为 0。
	 *      因此如果有线程并发地再次设置 PENDING，会导致无竞争路径的加锁失败
	 */
	if ((val & _Q_TAIL_MASK) == tail) {
		if (atomic_try_cmpxchg_relaxed(&lock->val, &val, _Q_LOCKED_VAL))
			goto release; /* No contention */
	}

	/*
	 * 要么是有其他线程排在我们后面，要么是 _Q_PENDING_VAL 被设置了
	 * 接下来它将检测到剩余的 tail 并排在我们后面，确保我们最终会看到一个 @next 指针
	 */
	set_locked(lock);

	/*
	 * 竞争路径：如果尚未看到 next 节点，则等待；之后释放锁
	 */
	if (!next)
		next = smp_cond_load_relaxed(&node->next, (VAL));

	arch_mcs_spin_unlock_contended(&next->locked);
	pv_kick_node(lock, next);

release:
	/*
	 * release the node
	 */
	__this_cpu_dec(qnodes[0].mcs.count);
}
EXPORT_SYMBOL(queued_spin_lock_slowpath);

/*
 * Generate the paravirt code for queued_spin_unlock_slowpath().
 */
#if !defined(_GEN_PV_LOCK_SLOWPATH) && defined(CONFIG_PARAVIRT_SPINLOCKS)
#define _GEN_PV_LOCK_SLOWPATH

#undef  pv_enabled
#define pv_enabled()	true

#undef pv_init_node
#undef pv_wait_node
#undef pv_kick_node
#undef pv_wait_head_or_lock

#undef  queued_spin_lock_slowpath
#define queued_spin_lock_slowpath	__pv_queued_spin_lock_slowpath

#include "qspinlock_paravirt.h"
#include "qspinlock.c"

bool nopvspin __initdata;
static __init int parse_nopvspin(char *arg)
{
	nopvspin = true;
	return 0;
}
early_param("nopvspin", parse_nopvspin);
#endif
