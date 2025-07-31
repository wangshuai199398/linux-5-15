// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic entry points for the idle threads and
 * implementation of the idle task scheduling class.
 *
 * (NOTE: these are not related to SCHED_IDLE batch scheduled
 *        tasks which are handled in sched/fair.c )
 */
#include "sched.h"

#include <trace/events/power.h>

/* Linker adds these: start and end of __cpuidle functions */
extern char __cpuidle_text_start[], __cpuidle_text_end[];

/**
 * sched_idle_set_state - Record idle state for the current CPU.
 * @idle_state: State to record.
 */
void sched_idle_set_state(struct cpuidle_state *idle_state)
{
	idle_set_state(this_rq(), idle_state);
}

static int __read_mostly cpu_idle_force_poll;

void cpu_idle_poll_ctrl(bool enable)
{
	if (enable) {
		cpu_idle_force_poll++;
	} else {
		cpu_idle_force_poll--;
		WARN_ON_ONCE(cpu_idle_force_poll < 0);
	}
}

#ifdef CONFIG_GENERIC_IDLE_POLL_SETUP
static int __init cpu_idle_poll_setup(char *__unused)
{
	cpu_idle_force_poll = 1;

	return 1;
}
__setup("nohlt", cpu_idle_poll_setup);

static int __init cpu_idle_nopoll_setup(char *__unused)
{
	cpu_idle_force_poll = 0;

	return 1;
}
__setup("hlt", cpu_idle_nopoll_setup);
#endif

static noinline int __cpuidle cpu_idle_poll(void)
{
	trace_cpu_idle(0, smp_processor_id());
	stop_critical_timings();
	rcu_idle_enter();
	local_irq_enable();

	while (!tif_need_resched() &&
	       (cpu_idle_force_poll || tick_check_broadcast_expired()))
		cpu_relax();

	rcu_idle_exit();
	start_critical_timings();
	trace_cpu_idle(PWR_EVENT_EXIT, smp_processor_id());

	return 1;
}

/* Weak implementations for optional arch specific functions */
void __weak arch_cpu_idle_prepare(void) { }
void __weak arch_cpu_idle_enter(void) { }
void __weak arch_cpu_idle_exit(void) { }
void __weak arch_cpu_idle_dead(void) { }
void __weak arch_cpu_idle(void)
{
	cpu_idle_force_poll = 1;
	raw_local_irq_enable();
}

/**
 * default_idle_call - Default CPU idle routine.
 *
 * To use when the cpuidle framework cannot be used.
 */
void __cpuidle default_idle_call(void)
{
	if (current_clr_polling_and_test()) {
		local_irq_enable();
	} else {

		trace_cpu_idle(1, smp_processor_id());
		stop_critical_timings();

		/*
		 * arch_cpu_idle() is supposed to enable IRQs, however
		 * we can't do that because of RCU and tracing.
		 *
		 * Trace IRQs enable here, then switch off RCU, and have
		 * arch_cpu_idle() use raw_local_irq_enable(). Note that
		 * rcu_idle_enter() relies on lockdep IRQ state, so switch that
		 * last -- this is very similar to the entry code.
		 */
		trace_hardirqs_on_prepare();
		lockdep_hardirqs_on_prepare();
		rcu_idle_enter();
		lockdep_hardirqs_on(_THIS_IP_);

		arch_cpu_idle();

		/*
		 * OK, so IRQs are enabled here, but RCU needs them disabled to
		 * turn itself back on.. funny thing is that disabling IRQs
		 * will cause tracing, which needs RCU. Jump through hoops to
		 * make it 'work'.
		 */
		raw_local_irq_disable();
		lockdep_hardirqs_off(_THIS_IP_);
		rcu_idle_exit();
		lockdep_hardirqs_on(_THIS_IP_);
		raw_local_irq_enable();

		start_critical_timings();
		trace_cpu_idle(PWR_EVENT_EXIT, smp_processor_id());
	}
}

static int call_cpuidle_s2idle(struct cpuidle_driver *drv,
			       struct cpuidle_device *dev)
{
	if (current_clr_polling_and_test())
		return -EBUSY;

	return cpuidle_enter_s2idle(drv, dev);
}

static int call_cpuidle(struct cpuidle_driver *drv, struct cpuidle_device *dev,
		      int next_state)
{
	/*
	 * The idle task must be scheduled, it is pointless to go to idle, just
	 * update no idle residency and return.
	 */
	if (current_clr_polling_and_test()) {
		dev->last_residency_ns = 0;
		local_irq_enable();
		return -EBUSY;
	}

	/*
	 * Enter the idle state previously returned by the governor decision.
	 * This function will block until an interrupt occurs and will take
	 * care of re-enabling the local interrupts
	 */
	return cpuidle_enter(drv, dev, next_state);
}

/**
 * cpuidle_idle_call - the main idle function
 *
 * NOTE: no locks or semaphores should be used here
 *
 * On architectures that support TIF_POLLING_NRFLAG, is called with polling
 * set, and it returns with polling set.  If it ever stops polling, it
 * must clear the polling bit.
 */
static void cpuidle_idle_call(void)
{
	struct cpuidle_device *dev = cpuidle_get_device();
	struct cpuidle_driver *drv = cpuidle_get_cpu_driver(dev);
	int next_state, entered_state;

	/*
	 * Check if the idle task must be rescheduled. If it is the
	 * case, exit the function after re-enabling the local irq.
	 */
	if (need_resched()) {
		local_irq_enable();
		return;
	}

	/*
	 * The RCU framework needs to be told that we are entering an idle
	 * section, so no more rcu read side critical sections and one more
	 * step to the grace period
	 */

	if (cpuidle_not_available(drv, dev)) {
		tick_nohz_idle_stop_tick();

		default_idle_call();
		goto exit_idle;
	}

	/*
	 * Suspend-to-idle ("s2idle") is a system state in which all user space
	 * has been frozen, all I/O devices have been suspended and the only
	 * activity happens here and in interrupts (if any). In that case bypass
	 * the cpuidle governor and go straight for the deepest idle state
	 * available.  Possibly also suspend the local tick and the entire
	 * timekeeping to prevent timer interrupts from kicking us out of idle
	 * until a proper wakeup interrupt happens.
	 */

	if (idle_should_enter_s2idle() || dev->forced_idle_latency_limit_ns) {
		u64 max_latency_ns;

		if (idle_should_enter_s2idle()) {

			entered_state = call_cpuidle_s2idle(drv, dev);
			if (entered_state > 0)
				goto exit_idle;

			max_latency_ns = U64_MAX;
		} else {
			max_latency_ns = dev->forced_idle_latency_limit_ns;
		}

		tick_nohz_idle_stop_tick();

		next_state = cpuidle_find_deepest_state(drv, dev, max_latency_ns);
		call_cpuidle(drv, dev, next_state);
	} else {
		bool stop_tick = true;

		/*
		 * Ask the cpuidle framework to choose a convenient idle state.
		 */
		next_state = cpuidle_select(drv, dev, &stop_tick);

		if (stop_tick || tick_nohz_tick_stopped())
			tick_nohz_idle_stop_tick();
		else
			tick_nohz_idle_retain_tick();

		entered_state = call_cpuidle(drv, dev, next_state);
		/*
		 * Give the governor an opportunity to reflect on the outcome
		 */
		cpuidle_reflect(dev, entered_state);
	}

exit_idle:
	__current_set_polling();

	/*
	 * It is up to the idle functions to reenable local interrupts
	 */
	if (WARN_ON_ONCE(irqs_disabled()))
		local_irq_enable();
}

/*
 * 通用的 idle 循环实现
 *
 * 在关闭轮询（polling）模式的情况下调用。
 * 用于在 CPU 没有任务可执行时执行“空闲”逻辑，是进入 idle 状态的核心路径之一
 */
static void do_idle(void)
{
	int cpu = smp_processor_id();

	/* 如果当前 CPU 是调度器中负责负载均衡的那一个，它会在 idle 时尝试执行任务迁移，减少不均衡 */
	nohz_run_idle_balance(cpu);

	/* 如果架构支持轮询位（polling bit），我们会保持以下不变性：
	 *
	 * 当当前 CPU 没有运行 idle 进程（即 rq->curr != rq->idle）时，轮询位应被清除
	 * 这意味着，如果 rq->idle 设置了轮询位（polling bit），那么只要设置了 need_resched 标志，就能确保该 CPU 会重新调度任务（reschedule）*/
	//设置 polling 状态并通知 NOHZ 子系统 CPU 即将进入 idle 状态，通知调度器当前 CPU 进入轮询模式，不依赖 tick 定时器中断
	__current_set_polling();
	// NOHZ 模式中关闭周期性 tick（timer tick）
	tick_nohz_idle_enter();
	// 进入主 idle 循环，直到有任务可运行（need_resched 被设置）
	while (!need_resched()) {
		rmb();
		// 关闭中断
		local_irq_disable();
		// 如果 CPU 已下线，停止 tick，报告 CPU 已进入死亡状态，并进入平台相关的“CPU 死亡”路径（如热插拔）
		if (cpu_is_offline(cpu)) {
			tick_nohz_idle_stop_tick();
			cpuhp_report_idle_dead();
			arch_cpu_idle_dead();
		}
		// 由架构层提供的钩子，用于执行平台相关 idle 前设置（如进入 C1/C2/C3）
		arch_cpu_idle_enter();
		// 确保 RCU 推迟的任务在 idle 前被唤醒
		rcu_nocb_flush_deferred_wakeup();

		/* 在轮询（poll）模式下，我们会重新开启中断并进行自旋。
		 * 同时，如果我们在从空闲状态被唤醒的路径中检测到 tick 广播设备已经为我们触发了中断，那么就不会进入深度空闲状态（deep idle），因为知道 IPI（中断请求）即将马上到达 */
		// 判断是否需要进入轮询或深度 idle：如果强制使用轮询（如调试）或 tick 广播设备已经过期，则启用轮询 idle（cpu_idle_poll()）
		if (cpu_idle_force_poll || tick_check_broadcast_expired()) {
			tick_nohz_idle_restart_tick();
			cpu_idle_poll();
		} else {
			// 否则调用 cpuidle 框架进入深度节能 idle 模式（如 C-states）
			cpuidle_idle_call();
		}
		// 从 idle 退出时恢复上下文
		arch_cpu_idle_exit();
	}

	/* 由于我们已经从上面的循环中跳出，可以确定 TIF_NEED_RESCHED 标志一定已经被设置，因此需要将其传递到 PREEMPT_NEED_RESCHED 中
	   这是必要的，因为对于轮询（polling）空闲循环来说，我们不会收到 IPI（中断）来帮我们合并调度状态，所以必须手动处理这个状态传递 */
	// 重新设置调度标志，清除 polling 状态
	preempt_set_need_resched();
	// 重新启用周期性 tick（NOHZ 退出）
	tick_nohz_idle_exit();
	// 清除 polling 状态
	__current_clr_polling();

	/* 我们承诺：如果在设置了轮询（polling）状态的同时，need_resched() 被设置，那么我们将调用 sched_ttwu_pending() 并进行重新调度（reschedule）
	   这意味着，在执行这些操作之前，必须确保清除 polling 状态对其他处理器是可见的（即内存可见性保证） */
	// 内存屏障确保 polling 清除对其他 CPU 可见
	smp_mb__after_atomic();

	/* RCU（Read-Copy Update）依赖于该调用在 RCU 读侧临界区之外执行 */
	// 处理在 idle 状态中接收到但尚未执行的跨核函数调用（如 smp_call_function()）
	flush_smp_call_function_from_idle();
	// 调用调度器，切换到真正的可运行任务（退出 idle）
	schedule_idle();
	// 如果启用了 livepatch（内核热补丁），进行补丁状态更新
	if (unlikely(klp_patch_pending(current)))
		klp_update_patch_state(current);
}

bool cpu_in_idle(unsigned long pc)
{
	return pc >= (unsigned long)__cpuidle_text_start &&
		pc < (unsigned long)__cpuidle_text_end;
}

struct idle_timer {
	struct hrtimer timer;
	int done;
};

static enum hrtimer_restart idle_inject_timer_fn(struct hrtimer *timer)
{
	struct idle_timer *it = container_of(timer, struct idle_timer, timer);

	WRITE_ONCE(it->done, 1);
	set_tsk_need_resched(current);

	return HRTIMER_NORESTART;
}

void play_idle_precise(u64 duration_ns, u64 latency_ns)
{
	struct idle_timer it;

	/*
	 * Only FIFO tasks can disable the tick since they don't need the forced
	 * preemption.
	 */
	WARN_ON_ONCE(current->policy != SCHED_FIFO);
	WARN_ON_ONCE(current->nr_cpus_allowed != 1);
	WARN_ON_ONCE(!(current->flags & PF_KTHREAD));
	WARN_ON_ONCE(!(current->flags & PF_NO_SETAFFINITY));
	WARN_ON_ONCE(!duration_ns);
	WARN_ON_ONCE(current->mm);

	rcu_sleep_check();
	preempt_disable();
	current->flags |= PF_IDLE;
	cpuidle_use_deepest_state(latency_ns);

	it.done = 0;
	hrtimer_init_on_stack(&it.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_HARD);
	it.timer.function = idle_inject_timer_fn;
	hrtimer_start(&it.timer, ns_to_ktime(duration_ns),
		      HRTIMER_MODE_REL_PINNED_HARD);

	while (!READ_ONCE(it.done))
		do_idle();

	cpuidle_use_deepest_state(0);
	current->flags &= ~PF_IDLE;

	preempt_fold_need_resched();
	preempt_enable();
}
EXPORT_SYMBOL_GPL(play_idle_precise);

void cpu_startup_entry(enum cpuhp_state state)
{
	arch_cpu_idle_prepare();
	cpuhp_online_idle(state);
	while (1)
		do_idle();//进入空闲循环（只要没有任务就不会退出）
}

/*
 * idle-task scheduling class.
 */

#ifdef CONFIG_SMP
static int
select_task_rq_idle(struct task_struct *p, int cpu, int flags)
{
	return task_cpu(p); /* IDLE tasks as never migrated */
}

static int
balance_idle(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	return WARN_ON_ONCE(1);
}
#endif

/*
 * Idle tasks are unconditionally rescheduled:
 */
static void check_preempt_curr_idle(struct rq *rq, struct task_struct *p, int flags)
{
	resched_curr(rq);
}

static void put_prev_task_idle(struct rq *rq, struct task_struct *prev)
{
}

static void set_next_task_idle(struct rq *rq, struct task_struct *next, bool first)
{
	update_idle_core(rq);
	schedstat_inc(rq->sched_goidle);
	queue_core_balance(rq);
}

#ifdef CONFIG_SMP
static struct task_struct *pick_task_idle(struct rq *rq)
{
	return rq->idle;
}
#endif

struct task_struct *pick_next_task_idle(struct rq *rq)
{
	struct task_struct *next = rq->idle;

	set_next_task_idle(rq, next, true);

	return next;
}

/*
 * It is not legal to sleep in the idle task - print a warning
 * message if some code attempts to do it:
 */
static void
dequeue_task_idle(struct rq *rq, struct task_struct *p, int flags)
{
	raw_spin_rq_unlock_irq(rq);
	printk(KERN_ERR "bad: scheduling from the idle thread!\n");
	dump_stack();
	raw_spin_rq_lock_irq(rq);
}

/*
 * scheduler tick hitting a task of our scheduling class.
 *
 * NOTE: This function can be called remotely by the tick offload that
 * goes along full dynticks. Therefore no local assumption can be made
 * and everything must be accessed through the @rq and @curr passed in
 * parameters.
 */
static void task_tick_idle(struct rq *rq, struct task_struct *curr, int queued)
{
}

static void switched_to_idle(struct rq *rq, struct task_struct *p)
{
	BUG();
}

static void
prio_changed_idle(struct rq *rq, struct task_struct *p, int oldprio)
{
	BUG();
}

static void update_curr_idle(struct rq *rq)
{
}

/*
 * Simple, special scheduling class for the per-CPU idle tasks:
 */
DEFINE_SCHED_CLASS(idle) = {

	/* no enqueue/yield_task for idle tasks */

	/* dequeue is not valid, we print a debug message there: */
	.dequeue_task		= dequeue_task_idle,

	.check_preempt_curr	= check_preempt_curr_idle,

	.pick_next_task		= pick_next_task_idle,
	.put_prev_task		= put_prev_task_idle,
	.set_next_task          = set_next_task_idle,

#ifdef CONFIG_SMP
	.balance		= balance_idle,
	.pick_task		= pick_task_idle,
	.select_task_rq		= select_task_rq_idle,
	.set_cpus_allowed	= set_cpus_allowed_common,
#endif

	.task_tick		= task_tick_idle,

	.prio_changed		= prio_changed_idle,
	.switched_to		= switched_to_idle,
	.update_curr		= update_curr_idle,
};
