/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IRQDESC_H
#define _LINUX_IRQDESC_H

#include <linux/rcupdate.h>
#include <linux/kobject.h>
#include <linux/mutex.h>

/*
 * Core internal functions to deal with irq descriptors
 */

struct irq_affinity_notify;
struct proc_dir_entry;
struct module;
struct irq_desc;
struct irq_domain;
struct pt_regs;

/**
 * 中断描述符
 * @irq_common_data:    每个中断和中断控制器相关的数据，会传递给中断芯片（chip）函数使用
 * @kstat_irqs:		    每个 CPU 的中断统计数据
 * @handle_irq:		    highlevel irq-events handler
 * @action:		        该中断的中断处理函数链（可以注册多个处理函数）。
 * @status_use_accessors: 中断状态信息（通过 accessor 函数访问）
 * @core_internal_state__do_not_mess_with_it: 内核内部状态信息（不要随意修改）
 * @depth:		        中断关闭深度，用于嵌套的 irq_disable() 调用
 * @wake_depth:		    中断唤醒使能深度，用于多个 irq_set_irq_wake() 调用者
 * @tot_count:		    用于非 per-CPU 中断的统计字段
 * @irq_count:		    用于检测中断是否“卡住”（stalled）的统计字段
 * @last_unhandled:	    用于处理未处理中断计数的老化定时器
 * @irqs_unhandled:	    未处理中断的统计字段，用于判断是否为伪中断
 * @threads_handled:    线程化处理程序的延迟伪中断检测用统计字段
 * @threads_handled_last: 线程化处理程序的延迟伪中断检测用比较字段
 * @lock:		        用于 SMP（多核）系统中的锁机制
 * @affinity_hint:	    用户空间设置的中断亲和性（affinity）提示
 * @affinity_notify:    当中断亲和性变化时的通知上下文
 * @pending_mask:	    待重新绑定（rebalance）的中断掩码
 * @threads_oneshot:    处理共享 oneshot 中断线程的位图
 * @threads_active:	    当前正在运行的中断处理线程数量
 * @wait_for_threads:   sync_irq() 使用的等待队列，用于等待线程处理完成
 * @nr_actions:		    该中断描述符上已安装的中断处理函数数量
 * @no_suspend_depth:   该描述符上带有 IRQF_NO_SUSPEND 标志的处理函数数量
 * @force_resume_depth: 该描述符上带有 IRQF_FORCE_RESUME 标志的处理函数数量
 * @rcu:		        用于延迟释放的 RCU 头
 * @kobj:		        用于在 sysfs 中表示该中断描述符的 kobject 对象
 * @request_mutex:	    在获取 desc->lock 之前用于保护中断申请/释放的互斥锁
 * @dir:		        该中断在 /proc/irq/ 中对应的 proc 文件目录项
 * @debugfs_file:	    对应 debugfs 中的文件节点
 * @name:		        中断流控制处理函数的名称，用于 /proc/interrupts 输出
 * 
 * 对于每一个中断，都有一个对中断的描述结构 struct irq_desc，它有一个重要的成员变量是 struct irqaction，用于表示处理这个中断的动作
 */
struct irq_desc {
	struct irq_common_data	irq_common_data;
	struct irq_data		irq_data;
	unsigned int __percpu	*kstat_irqs;
	irq_flow_handler_t	handle_irq;
	struct irqaction	*action;	/* IRQ action list */
	unsigned int		status_use_accessors;
	unsigned int		core_internal_state__do_not_mess_with_it;
	unsigned int		depth;		/* nested irq disables */
	unsigned int		wake_depth;	/* nested wake enables */
	unsigned int		tot_count;
	unsigned int		irq_count;	/* For detecting broken IRQs */
	unsigned long		last_unhandled;	/* Aging timer for unhandled count */
	unsigned int		irqs_unhandled;
	atomic_t		threads_handled;
	int			threads_handled_last;
	raw_spinlock_t		lock;
	struct cpumask		*percpu_enabled;
	const struct cpumask	*percpu_affinity;
#ifdef CONFIG_SMP
	const struct cpumask	*affinity_hint;
	struct irq_affinity_notify *affinity_notify;
#ifdef CONFIG_GENERIC_PENDING_IRQ
	cpumask_var_t		pending_mask;
#endif
#endif
	unsigned long		threads_oneshot;
	atomic_t		threads_active;
	wait_queue_head_t       wait_for_threads;
#ifdef CONFIG_PM_SLEEP
	unsigned int		nr_actions;
	unsigned int		no_suspend_depth;
	unsigned int		cond_suspend_depth;
	unsigned int		force_resume_depth;
#endif
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry	*dir;
#endif
#ifdef CONFIG_GENERIC_IRQ_DEBUGFS
	struct dentry		*debugfs_file;
	const char		*dev_name;
#endif
#ifdef CONFIG_SPARSE_IRQ
	struct rcu_head		rcu;
	struct kobject		kobj;
#endif
	struct mutex		request_mutex;
	int			parent_irq;
	struct module		*owner;
	const char		*name;
} ____cacheline_internodealigned_in_smp;

#ifdef CONFIG_SPARSE_IRQ
extern void irq_lock_sparse(void);
extern void irq_unlock_sparse(void);
#else
static inline void irq_lock_sparse(void) { }
static inline void irq_unlock_sparse(void) { }
extern struct irq_desc irq_desc[NR_IRQS];
#endif

static inline unsigned int irq_desc_kstat_cpu(struct irq_desc *desc,
					      unsigned int cpu)
{
	return desc->kstat_irqs ? *per_cpu_ptr(desc->kstat_irqs, cpu) : 0;
}

static inline struct irq_desc *irq_data_to_desc(struct irq_data *data)
{
	return container_of(data->common, struct irq_desc, irq_common_data);
}

static inline unsigned int irq_desc_get_irq(struct irq_desc *desc)
{
	return desc->irq_data.irq;
}

static inline struct irq_data *irq_desc_get_irq_data(struct irq_desc *desc)
{
	return &desc->irq_data;
}

static inline struct irq_chip *irq_desc_get_chip(struct irq_desc *desc)
{
	return desc->irq_data.chip;
}

static inline void *irq_desc_get_chip_data(struct irq_desc *desc)
{
	return desc->irq_data.chip_data;
}

static inline void *irq_desc_get_handler_data(struct irq_desc *desc)
{
	return desc->irq_common_data.handler_data;
}

/*
 * Architectures call this to let the generic IRQ layer handle an interrupt.
 * 这里的 handle_irq，最终会调用 __handle_irq_event_percpu
 */
static inline void generic_handle_irq_desc(struct irq_desc *desc)
{
	desc->handle_irq(desc);
}

int handle_irq_desc(struct irq_desc *desc);
int generic_handle_irq(unsigned int irq);

#ifdef CONFIG_IRQ_DOMAIN
/*
 * Convert a HW interrupt number to a logical one using a IRQ domain,
 * and handle the result interrupt number. Return -EINVAL if
 * conversion failed.
 */
int generic_handle_domain_irq(struct irq_domain *domain, unsigned int hwirq);

#ifdef CONFIG_HANDLE_DOMAIN_IRQ
int handle_domain_irq(struct irq_domain *domain,
		      unsigned int hwirq, struct pt_regs *regs);

int handle_domain_nmi(struct irq_domain *domain, unsigned int hwirq,
		      struct pt_regs *regs);
#endif
#endif

/* Test to see if a driver has successfully requested an irq */
static inline int irq_desc_has_action(struct irq_desc *desc)
{
	return desc && desc->action != NULL;
}

/**
 * irq_set_handler_locked - Set irq handler from a locked region
 * @data:	Pointer to the irq_data structure which identifies the irq
 * @handler:	Flow control handler function for this interrupt
 *
 * Sets the handler in the irq descriptor associated to @data.
 *
 * Must be called with irq_desc locked and valid parameters. Typical
 * call site is the irq_set_type() callback.
 */
static inline void irq_set_handler_locked(struct irq_data *data,
					  irq_flow_handler_t handler)
{
	struct irq_desc *desc = irq_data_to_desc(data);

	desc->handle_irq = handler;
}

/**
 * irq_set_chip_handler_name_locked - Set chip, handler and name from a locked region
 * @data:	Pointer to the irq_data structure for which the chip is set
 * @chip:	Pointer to the new irq chip
 * @handler:	Flow control handler function for this interrupt
 * @name:	Name of the interrupt
 *
 * Replace the irq chip at the proper hierarchy level in @data and
 * sets the handler and name in the associated irq descriptor.
 *
 * Must be called with irq_desc locked and valid parameters.
 */
static inline void
irq_set_chip_handler_name_locked(struct irq_data *data, struct irq_chip *chip,
				 irq_flow_handler_t handler, const char *name)
{
	struct irq_desc *desc = irq_data_to_desc(data);

	desc->handle_irq = handler;
	desc->name = name;
	data->chip = chip;
}

bool irq_check_status_bit(unsigned int irq, unsigned int bitmask);

static inline bool irq_balancing_disabled(unsigned int irq)
{
	return irq_check_status_bit(irq, IRQ_NO_BALANCING_MASK);
}

static inline bool irq_is_percpu(unsigned int irq)
{
	return irq_check_status_bit(irq, IRQ_PER_CPU);
}

static inline bool irq_is_percpu_devid(unsigned int irq)
{
	return irq_check_status_bit(irq, IRQ_PER_CPU_DEVID);
}

void __irq_set_lockdep_class(unsigned int irq, struct lock_class_key *lock_class,
			     struct lock_class_key *request_class);
static inline void
irq_set_lockdep_class(unsigned int irq, struct lock_class_key *lock_class,
		      struct lock_class_key *request_class)
{
	if (IS_ENABLED(CONFIG_LOCKDEP))
		__irq_set_lockdep_class(irq, lock_class, request_class);
}

#endif
