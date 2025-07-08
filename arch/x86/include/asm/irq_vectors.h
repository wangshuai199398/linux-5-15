/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_IRQ_VECTORS_H
#define _ASM_X86_IRQ_VECTORS_H

#include <linux/threads.h>
/*
 * Linux IRQ 向量布局（IRQ vector layout）
 *
 * 每个 CPU 有 256 个 IDT（中断描述符表）条目，每个条目占 8 字节
 * Linux 可以定义这 256 个条目，它们被 CPU 用作跳转表：当某个中断向量被触发（不论是来自 CPU 外部、内部，还是由软件触发）时，CPU 会根据 IDT 跳转到对应的处理函数
 *
 * Linux 在系统启动早期就为每个条目设置了跳转的内核代码地址，并且从不再改变这些设置。
 * 下面是 IDT 条目（中断向量）的通用布局：
 *
 *  Vectors   0 ...  31 : 系统陷入或者系统异常，这些错误无法屏蔽，一定要处理 - trap_init 中设置了中断处理函数
 *  Vectors  32 ... 127 : 设备中断 - 由外部设备触发的中断
 *  Vector  128         : 传统的 int80 系统调用接口
 *  Vectors 129 ... LOCAL_TIMER_VECTOR-1
 *  Vectors LOCAL_TIMER_VECTOR ... 255 : 特殊中断
 *
 * 在 64 位 x86 架构中，每个 CPU 都有独立的 IDT 表；而在 32 位架构中，所有 CPU 共享一个 IDT 表
 *
 * 该文件中列出了这些中断向量的具体布局
 */

/* 这用于在编程 APIC（高级可编程中断控制器）时指定中断向量 */
#define NMI_VECTOR			0x02

/*
 * IDT vectors usable for external interrupt sources start at 0x20.
 * (0x80 is the syscall vector, 0x30-0x3f are for ISA)
 */
#define FIRST_EXTERNAL_VECTOR		0x20

/*
 * Reserve the lowest usable vector (and hence lowest priority)  0x20 for
 * triggering cleanup after irq migration. 0x21-0x2f will still be used
 * for device interrupts.
 */
#define IRQ_MOVE_CLEANUP_VECTOR		FIRST_EXTERNAL_VECTOR

#define IA32_SYSCALL_VECTOR		0x80

/*
 * Vectors 0x30-0x3f are used for ISA interrupts.
 *   round up to the next 16-vector boundary
 */
#define ISA_IRQ_VECTOR(irq)		(((FIRST_EXTERNAL_VECTOR + 16) & ~15) + irq)

/*
 * Special IRQ vectors used by the SMP architecture, 0xf0-0xff
 *
 *  some of the following vectors are 'rare', they are merged
 *  into a single vector (CALL_FUNCTION_VECTOR) to save vector space.
 *  TLB, reschedule and local APIC vectors are performance-critical.
 */

#define SPURIOUS_APIC_VECTOR		0xff
/*
 * Sanity check
 */
#if ((SPURIOUS_APIC_VECTOR & 0x0F) != 0x0F)
# error SPURIOUS_APIC_VECTOR definition error
#endif

#define ERROR_APIC_VECTOR		0xfe
#define RESCHEDULE_VECTOR		0xfd
#define CALL_FUNCTION_VECTOR		0xfc
#define CALL_FUNCTION_SINGLE_VECTOR	0xfb
#define THERMAL_APIC_VECTOR		0xfa
#define THRESHOLD_APIC_VECTOR		0xf9
#define REBOOT_VECTOR			0xf8

/*
 * Generic system vector for platform specific use
 */
#define X86_PLATFORM_IPI_VECTOR		0xf7

/*
 * IRQ work vector:
 */
#define IRQ_WORK_VECTOR			0xf6

/* 0xf5 - unused, was UV_BAU_MESSAGE */
#define DEFERRED_ERROR_VECTOR		0xf4

/* Vector on which hypervisor callbacks will be delivered */
#define HYPERVISOR_CALLBACK_VECTOR	0xf3

/* Vector for KVM to deliver posted interrupt IPI */
#ifdef CONFIG_HAVE_KVM
#define POSTED_INTR_VECTOR		0xf2
#define POSTED_INTR_WAKEUP_VECTOR	0xf1
#define POSTED_INTR_NESTED_VECTOR	0xf0
#endif

#define MANAGED_IRQ_SHUTDOWN_VECTOR	0xef

#if IS_ENABLED(CONFIG_HYPERV)
#define HYPERV_REENLIGHTENMENT_VECTOR	0xee
#define HYPERV_STIMER0_VECTOR		0xed
#endif

#define LOCAL_TIMER_VECTOR		0xec
//CPU 能够处理的中断总共 256 个
#define NR_VECTORS			 256

#ifdef CONFIG_X86_LOCAL_APIC
#define FIRST_SYSTEM_VECTOR		LOCAL_TIMER_VECTOR
#else
#define FIRST_SYSTEM_VECTOR		NR_VECTORS
#endif

#define NR_EXTERNAL_VECTORS		(FIRST_SYSTEM_VECTOR - FIRST_EXTERNAL_VECTOR)
#define NR_SYSTEM_VECTORS		(NR_VECTORS - FIRST_SYSTEM_VECTOR)

/*
 * Size the maximum number of interrupts.
 *
 * If the irq_desc[] array has a sparse layout, we can size things
 * generously - it scales up linearly with the maximum number of CPUs,
 * and the maximum number of IO-APICs, whichever is higher.
 *
 * In other cases we size more conservatively, to not create too large
 * static arrays.
 */

#define NR_IRQS_LEGACY			16

#define CPU_VECTOR_LIMIT		(64 * NR_CPUS)
#define IO_APIC_VECTOR_LIMIT		(32 * MAX_IO_APICS)

#if defined(CONFIG_X86_IO_APIC) && defined(CONFIG_PCI_MSI)
#define NR_IRQS						\
	(CPU_VECTOR_LIMIT > IO_APIC_VECTOR_LIMIT ?	\
		(NR_VECTORS + CPU_VECTOR_LIMIT)  :	\
		(NR_VECTORS + IO_APIC_VECTOR_LIMIT))
#elif defined(CONFIG_X86_IO_APIC)
#define	NR_IRQS				(NR_VECTORS + IO_APIC_VECTOR_LIMIT)
#elif defined(CONFIG_PCI_MSI)
#define NR_IRQS				(NR_VECTORS + CPU_VECTOR_LIMIT)
#else
#define NR_IRQS				NR_IRQS_LEGACY
#endif

#endif /* _ASM_X86_IRQ_VECTORS_H */
