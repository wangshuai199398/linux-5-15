// SPDX-License-Identifier: GPL-2.0
#include <linux/linkage.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/timex.h>
#include <linux/random.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/device.h>
#include <linux/bitops.h>
#include <linux/acpi.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/pgtable.h>

#include <linux/atomic.h>
#include <asm/timer.h>
#include <asm/hw_irq.h>
#include <asm/desc.h>
#include <asm/io_apic.h>
#include <asm/acpi.h>
#include <asm/apic.h>
#include <asm/setup.h>
#include <asm/i8259.h>
#include <asm/traps.h>
#include <asm/prom.h>

/*
 * ISA PIC or low IO-APIC triggered (INTA-cycle or APIC) interrupts:
 * (these are usually mapped to vectors 0x30-0x3f)
 */

/*
 * The IO-APIC gives us many more interrupt sources. Most of these
 * are unused but an SMP system is supposed to have enough memory ...
 * sometimes (mostly wrt. hw bugs) we get corrupted vectors all
 * across the spectrum, so we really want to be prepared to get all
 * of these. Plus, more powerful systems might have more than 64
 * IO-APIC registers.
 *
 * (these are usually mapped into the 0x30-0xff vector range)
 */
/*
vector_irq 是一个长度为 256（NR_VECTORS）的整型数组，每个元素表示一个向量号和其对应的 IRQ 号的映射关系
每个 CPU 都会维护一个长度为 256 的 vector_irq 数组，用于记录从中断向量号到 IRQ 号的映射关系。
在中断发生时，内核会通过当前 CPU 的 vector_irq 数组，根据中断向量号查找对应的 IRQ，进而找到相关的中断处理程序

vector_irq 数组会在处理外部硬件中断的初始阶段被使用，在 arch/x86/kernel/irq.c 文件中的 do_IRQ 函数中可以看到它的用法
*/
DEFINE_PER_CPU(vector_irq_t, vector_irq) = {
	[0 ... NR_VECTORS - 1] = VECTOR_UNUSED,
};
/*
初始化 legacy 中断控制器，并通过 irq_set_chip_and_handler 为每个中断设置 chip 和 handler
*/
void __init init_ISA_irqs(void)
{
	// irq_chip 用于表示硬件中断芯片的描述符
	struct irq_chip *chip = legacy_pic->chip;
	int i;

	/*
	 * Try to set up the through-local-APIC virtual wire mode earlier.
	 *
	 * On some 32-bit UP machines, whose APIC has been disabled by BIOS
	 * and then got re-enabled by "lapic", it hangs at boot time without this.
	 * 用于初始化引导处理器（即最先启动的处理器）的 APIC（高级可编程中断控制器）
	 */
	init_bsp_APIC();
	// 初始化传统的可编程中断控制器（PIC） init_8259A
	legacy_pic->init(0);
	// 为每个传统中断（legacy irq）设置对应的传统中断芯片（chip）和中断处理函数（handler）
	for (i = 0; i < nr_legacy_irqs(); i++) {
		irq_set_chip_and_handler(i, chip, handle_level_irq);
		irq_set_status_flags(i, IRQ_LEVEL);
	}
}
//初始化其他的设备中断
void __init init_IRQ(void)
{
	int i;

	/*
	 * On cpu 0, Assign ISA_IRQ_VECTOR(irq) to IRQ 0..15.
	 * If these IRQ's are handled by legacy interrupt-controllers like PIC,
	 * then this configuration will likely be static after the boot. If
	 * these IRQs are handled by more modern controllers like IO-APIC,
	 * then this vector space can be freed and re-used dynamically as the
	 * irq's migrate etc.
	 * 用传统中断（legacy interrupts）的向量号来填充 vector_irq 这个每 CPU（percpu）的数组
	 */
	for (i = 0; i < nr_legacy_irqs(); i++)
		per_cpu(vector_irq, 0)[ISA_IRQ_VECTOR(i)] = irq_to_desc(i);

	BUG_ON(irq_init_percpu_irqstack(smp_processor_id()));

	x86_init.irqs.intr_init();//native_init_IRQ
}
// 完成局部 APIC 和 ISA 中断的初始化
void __init native_init_IRQ(void)
{
	/* Execute any quirks before the call gates are initialised: */
	// init_ISA_irqs 初始化 ISA 中断
	x86_init.irqs.pre_vector_init();

	idt_setup_apic_and_irq_gates();
	lapic_assign_system_vectors();
	//如果系统没有使用 ACPI 或设备树提供的 I/O APIC，且系统中存在传统中断控制器（比如 8259A）
	if (!acpi_ioapic && !of_ioapic && nr_legacy_irqs()) {
		/* IRQ 2 是用于连接第二个中断控制器（如第二个 8259A）的级联中断线路
		   向内核注册 IRQ 2 中断处理器
		   使用 no_action 作为处理函数（即这个中断不会真正处理任何事情）
		   IRQF_NO_THREAD 表示不为该中断创建线程（非线程化中断）
		   名称为 "cascade"，最后一个参数为 NULL（无设备结构体）
		*/
		if (request_irq(2, no_action, IRQF_NO_THREAD, "cascade", NULL))
			pr_err("%s: request_irq() failed\n", "cascade");
	}
}
