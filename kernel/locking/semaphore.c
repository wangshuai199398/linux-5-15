// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2008 Intel Corporation
 * Author: Matthew Wilcox <willy@linux.intel.com>
 *
 * This file implements counting semaphores.
 * A counting semaphore may be acquired 'n' times before sleeping.
 * See mutex.c for single-acquisition sleeping locks which enforce
 * rules which allow code to be debugged more easily.
 */

/*
 * Some notes on the implementation:
 *
 * The spinlock controls access to the other members of the semaphore.
 * down_trylock() and up() can be called from interrupt context, so we
 * have to disable interrupts when taking the lock.  It turns out various
 * parts of the kernel expect to be able to use down() on a semaphore in
 * interrupt context when they know it will succeed, so we have to use
 * irqsave variants for down(), down_interruptible() and down_killable()
 * too.
 *
 * The ->count variable represents how many more tasks can acquire this
 * semaphore.  If it's zero, there may be tasks waiting on the wait_list.
 */

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/ftrace.h>

static noinline void __down(struct semaphore *sem);
static noinline int __down_interruptible(struct semaphore *sem);
static noinline int __down_killable(struct semaphore *sem);
static noinline int __down_timeout(struct semaphore *sem, long timeout);
static noinline void __up(struct semaphore *sem);

/**
 * down - acquire the semaphore
 * @sem: the semaphore to be acquired
 *
 * Acquires the semaphore.  If no more tasks are allowed to acquire the
 * semaphore, calling this function will put the task to sleep until the
 * semaphore is released.
 *
 * Use of this function is deprecated, please use down_interruptible() or
 * down_killable() instead.
 */
void down(struct semaphore *sem)
{
	unsigned long flags;

	might_sleep();
	raw_spin_lock_irqsave(&sem->lock, flags);
	if (likely(sem->count > 0))
		sem->count--;
	else
		__down(sem);
	raw_spin_unlock_irqrestore(&sem->lock, flags);
}
EXPORT_SYMBOL(down);

/**
 * down_interruptible - acquire the semaphore unless interrupted
 * @sem: the semaphore to be acquired
 *
 * Attempts to acquire the semaphore.  If no more tasks are allowed to
 * acquire the semaphore, calling this function will put the task to sleep.
 * If the sleep is interrupted by a signal, this function will return -EINTR.
 * If the semaphore is successfully acquired, this function returns 0.
 * 获取信号量并减少计数，同时当前任务也会被调度到受阻状态
 * 也就是说 TASK_INTERRUPTIBLE 标志将会被至位。TASK_INTERRUPTIBLE 表示这个进程也许可以通过 信号 退回到销毁状态
 * semaphore_wangs
 */
int down_interruptible(struct semaphore *sem)
{
	unsigned long flags;
	int result = 0;

	might_sleep();
	raw_spin_lock_irqsave(&sem->lock, flags);
	if (likely(sem->count > 0))
		sem->count--;
	else
		result = __down_interruptible(sem);
	raw_spin_unlock_irqrestore(&sem->lock, flags);

	return result;
}
EXPORT_SYMBOL(down_interruptible);

/**
 * down_killable - acquire the semaphore unless killed
 * @sem: the semaphore to be acquired
 *
 * Attempts to acquire the semaphore.  If no more tasks are allowed to
 * acquire the semaphore, calling this function will put the task to sleep.
 * If the sleep is interrupted by a fatal signal, this function will return
 * -EINTR.  If the semaphore is successfully acquired, this function returns 0.
 * 与 down_interruptible 类似，但是它还将当前进程的 TASK_KILLABLE 标志置位。这表示等待的进程可以被杀死信号中断
 */
int down_killable(struct semaphore *sem)
{
	unsigned long flags;
	int result = 0;

	might_sleep();
	raw_spin_lock_irqsave(&sem->lock, flags);
	if (likely(sem->count > 0))
		sem->count--;
	else
		result = __down_killable(sem);
	raw_spin_unlock_irqrestore(&sem->lock, flags);

	return result;
}
EXPORT_SYMBOL(down_killable);

/**
 * down_trylock - try to acquire the semaphore, without waiting
 * @sem: the semaphore to be acquired
 *
 * Try to acquire the semaphore atomically.  Returns 0 if the semaphore has
 * been acquired successfully or 1 if it cannot be acquired.
 *
 * NOTE: This return value is inverted from both spin_trylock and
 * mutex_trylock!  Be careful about this when converting code.
 *
 * Unlike mutex_trylock, this function can be used from interrupt context,
 * and the semaphore can be released by any task or interrupt.
 * 获取一个锁，如果信号量当前为 0（不可用），立即返回，不睡眠、不排队
 */
int down_trylock(struct semaphore *sem)
{
	unsigned long flags;
	int count;

	raw_spin_lock_irqsave(&sem->lock, flags);
	count = sem->count - 1;
	if (likely(count >= 0))
		sem->count = count;
	raw_spin_unlock_irqrestore(&sem->lock, flags);

	return (count < 0);
}
EXPORT_SYMBOL(down_trylock);

/**
 * down_timeout - acquire the semaphore within a specified time
 * @sem: the semaphore to be acquired
 * @timeout: how long to wait before failing
 *
 * Attempts to acquire the semaphore.  If no more tasks are allowed to
 * acquire the semaphore, calling this function will put the task to sleep.
 * If the semaphore is not released within the specified number of jiffies,
 * this function returns -ETIME.  It returns 0 if the semaphore was acquired.
 * 试图去获取一个锁，阻塞，但有限时：在等待 timeout 时间内，信号量如果变为可用则成功获取
 */
int down_timeout(struct semaphore *sem, long timeout)
{
	unsigned long flags;
	int result = 0;

	might_sleep();
	raw_spin_lock_irqsave(&sem->lock, flags);
	if (likely(sem->count > 0))
		sem->count--;
	else
		result = __down_timeout(sem, timeout);
	raw_spin_unlock_irqrestore(&sem->lock, flags);

	return result;
}
EXPORT_SYMBOL(down_timeout);

/**
 * up - 释放信号量
 * @sem: the semaphore to release
 *
 * 与互斥锁（mutex）不同，up() 可以在 任何上下文中调用，甚至可以由 从未调用过 down() 的任务 来调用
 */
void up(struct semaphore *sem)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&sem->lock, flags);
	if (likely(list_empty(&sem->wait_list)))
		sem->count++;
	else
		__up(sem);
	raw_spin_unlock_irqrestore(&sem->lock, flags);
}
EXPORT_SYMBOL(up);

/* Functions for the contended case */

struct semaphore_waiter {
	struct list_head list;
	struct task_struct *task;
	bool up;
};

/*
 * 由于这个函数是内联的，state 参数将是常量，因此会被编译器优化掉。同样，对于没有超时的情况，timeout 参数也会被优化掉
 * 在信号量资源不可用（count ≤ 0）时，将当前进程加入等待队列，并进行阻塞睡眠，直到资源可用或被信号中断
 */
static inline int __sched __down_common(struct semaphore *sem, long state,
								long timeout)
{
	struct semaphore_waiter waiter;
	// 将当前进程加入到 wait_list
	list_add_tail(&waiter.list, &sem->wait_list);
	waiter.task = current;
	waiter.up = false;
	// 如果一个函数想要获取一个已经被其它任务获取的锁，它将会转入到无限循环。并且它不能被信号中断，当前设置的超时不会过期或者当前持有锁的任务不释放它
	for (;;) {
		if (signal_pending_state(state, current))
			goto interrupted;
		// 没有挂起信号，我们检测超时是否小于等于零
		if (unlikely(timeout <= 0))
			goto timed_out;
		// 当前的任务将会被设置为传入的 state
		__set_current_state(state);
		raw_spin_unlock_irq(&sem->lock);
		// 将当前的任务置为休眠到设置的超时为止
		timeout = schedule_timeout(timeout);
		raw_spin_lock_irq(&sem->lock);
		if (waiter.up)
			return 0;
	}

 timed_out:
	list_del(&waiter.list);
	return -ETIME;
 // 删除等待锁的列表，然后返回 -EINTR 错误码
 interrupted:
	list_del(&waiter.list);
	return -EINTR;
}

static noinline void __sched __down(struct semaphore *sem)
{
	__down_common(sem, TASK_UNINTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
}

static noinline int __sched __down_interruptible(struct semaphore *sem)
{
	return __down_common(sem, TASK_INTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
}

static noinline int __sched __down_killable(struct semaphore *sem)
{
	return __down_common(sem, TASK_KILLABLE, MAX_SCHEDULE_TIMEOUT);
}

static noinline int __sched __down_timeout(struct semaphore *sem, long timeout)
{
	return __down_common(sem, TASK_UNINTERRUPTIBLE, timeout);
}

static noinline void __sched __up(struct semaphore *sem)
{
	// 获取待序列中的第一个任务，将它从列表中删除
	struct semaphore_waiter *waiter = list_first_entry(&sem->wait_list,
						struct semaphore_waiter, list);
	list_del(&waiter->list);
	// 从此刻起 __down_common 函数中的无限循环将会被停止
	waiter->up = true;
	// 唤醒任务
	wake_up_process(waiter->task);
}
