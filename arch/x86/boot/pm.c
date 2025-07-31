// SPDX-License-Identifier: GPL-2.0-only
/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *
 * ----------------------------------------------------------------------- */

/*
 * Prepare the machine for transition to protected mode.
 */

#include "boot.h"
#include <asm/segment.h>

/*
 * Invoke the realmode switch hook if present; otherwise disable all interrupts.
 * 如果发现 realmode_switch hook， 那么将调用它并禁止 NMI 中断，反之将直接禁止 NMI 中断。只有当 bootloader 运行在宿主环境下（比如在 DOS 下运行 ）， hook 才会被使用
 * NMI 中断是一类特殊的中断，往往预示着系统发生了不可恢复的错误，所以在正常运行的操作系统中，NMI 中断是不会被禁止的，但是在进入保护模式之前，由于特殊需求，代码禁止了这类中断
 */
static void realmode_switch_hook(void)
{
	//realmode_switch 指向了一个16 位实模式代码地址（远跳转指针），这个16位代码将禁止 NMI 中断
	if (boot_params.hdr.realmode_swtch) {
		//用了 lcallw 指令进行远函数调用
		asm volatile("lcallw *%0"
			     : : "m" (boot_params.hdr.realmode_swtch)
			     : "eax", "ebx", "ecx", "edx");
	} else {
		//调用 cli 汇编指令清除了中断标志 IF，这条指令执行之后，外部中断就被禁止了，紧接着的下一行代码就禁止了 NMI 中断
		asm volatile("cli");
		//通过写 0x80 进 CMOS 地址寄存器 0x70
		outb(0x80, 0x70); /* Disable NMI */
		//进行短暂的延时以等待 I/O 操作完成
		io_delay();
	}
}

/*
 * Disable all interrupts at the legacy PIC.
 * 屏蔽了从中断控制器 (注：中断控制器的原文是 Programmable Interrupt Controller) 的所有中断，
 * 和主中断控制器上除IRQ2以外的所有中断（IRQ2是主中断控制器上的级联中断，所有从中断控制器的中断将通过这个级联中断报告给 CPU ）
 */
static void mask_all_interrupts(void)
{
	outb(0xff, 0xa1);	/* Mask all interrupts on the secondary PIC */
	io_delay();
	outb(0xfb, 0x21);	/* Mask all but cascade on the primary PIC */
	io_delay();
}

/*
 * Reset IGNNE# if asserted in the FPU.
 * 将 0 写入 I/O 端口 0xf0 和 0xf1 以复位数字协处理器
 */
static void reset_coprocessor(void)
{
	outb(0, 0xf0);
	io_delay();
	outb(0, 0xf1);
	io_delay();
}

/*
 * Set up the GDT
 * __attribute__((packed)) 意味着这个结构就只包含 48 bit 信息（没有字节对齐优化）
 * 表示了一个48-bit的特殊功能寄存器 GDTR，其包含了全局描述符表 Global Descriptor的基地址
 */

struct gdt_ptr {
	u16 len;
	u32 ptr;
} __attribute__((packed));

/*
使用 boot_gdt 数组定义了需要引入 GDTR 寄存器的段描述符信息
在 boot_gdt 中，定义了代码，数据和 TSS 段(Task State Segment, 任务状态段)的段描述符，因为并没有设置任何的中断调用（记得上面说的 null_idt吗？），
所以 TSS 段并不会被使用到。TSS 段存在的唯一目的就是让 Intel 处理器能够正确进入保护模式
__attribute__((aligned(16))) 修饰，意味着这个数组将以 16 字节为单位对齐
*/
static void setup_gdt(void)
{
	/* There are machines which are known to not boot with the GDT being 8-byte unaligned.  Intel recommends 16 byte alignment. */
	//有2个空项，第一项是一个空的描述符，第二项在代码中没有使用
	static const u64 boot_gdt[] __attribute__((aligned(16))) = {
		/* CS: code, read/execute, 4 GB, base 0 */
		// 基地址是 0， 段长度是 0xfffff （ 1 MB ），而标志字段展开之后是下面的二进制数据 1100 0000 1001 1011
		[GDT_ENTRY_BOOT_CS] = GDT_ENTRY(0xc09b, 0, 0xfffff),
		/* DS: data, read/write, 4 GB, base 0 */
		[GDT_ENTRY_BOOT_DS] = GDT_ENTRY(0xc093, 0, 0xfffff),
		/* TSS: 32-bit tss, 104 bytes, base 4096 */
		/* We only have a TSS here to keep Intel VT happy;
		   we don't actually use it for anything. */
		[GDT_ENTRY_BOOT_TSS] = GDT_ENTRY(0x0089, 4096, 103),
	};
	/* Xen HVM incorrectly stores a pointer to the gdt_ptr, instead
	   of the gdt_ptr contents.  Thus, make it static so it will
	   stay in memory, at least long enough that we switch to the
	   proper kernel GDT. */
	static struct gdt_ptr gdt;
	//获取 GDT 的长度
	gdt.len = sizeof(boot_gdt)-1;
	//将 GDT 的地址放入 gdt.ptr 中，这里的地址计算很简单，因为我们还在实模式，所以就是 （ ds << 4 + 数组起始地址）
	gdt.ptr = (u32)&boot_gdt + (ds() << 4);
	//执行 lgdtl 指令将 GDT 信息写入 GDTR 寄存器
	asm volatile("lgdtl %0" : : "m" (gdt));
}

/*
 * Set up the IDT
 * 使用 lidtl 指令将 null_idt 所指向的中断描述符表引入寄存器 IDT。
 * 由于 null_idt 没有设定中断描述符表的长度（长度为 0 ），所以这段指令执行之后，实际上没有任何中断调用被设置成功（所有中断调用都是空的）
 * null_idt 是一个 gdt_ptr 结构的数据
 */
static void setup_idt(void)
{
	static const struct gdt_ptr null_idt = {0, 0};
	asm volatile("lidtl %0" : : "m" (null_idt));
}

/*
 * 进行最后的准备工作然后进入保护模式
 */
void go_to_protected_mode(void)
{
	/* 在离开实模式之前的hook，同时禁用中断 */
	realmode_switch_hook();

	/* 使能 A20 gate */
	if (enable_a20()) {
		puts("A20 gate not responding, unable to boot...\n");
		die();
	}

	/* Reset coprocessor (IGNNE#) */
	reset_coprocessor();

	/* Mask all interrupts in the PIC */
	mask_all_interrupts();

	/* Actual transition to protected mode... */
	//设置中断描述符表（ IDT ）
	setup_idt();
	//设置全局描述符表
	setup_gdt();
	//从实模式到保护模式的跳转，第一个参数是 保护模式代码的入口，保存在 eax 寄存器，第二个参数是 boot_params 结构的地址，保存在 edx 寄存器 
	protected_mode_jump(boot_params.hdr.code32_start,
			    (u32)&boot_params + (ds() << 4));
}
