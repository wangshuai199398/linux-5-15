// SPDX-License-Identifier: GPL-2.0-only
/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *   Copyright 2009 Intel Corporation; author H. Peter Anvin
 *
 * ----------------------------------------------------------------------- */

/*
 * Main module for the real-mode kernel code
 */
#include <linux/build_bug.h>

#include "boot.h"
#include "string.h"
//包含setup_header hdr，这个结构包含了linux boot protocol中定义的相同字段并且由boot loader填写
struct boot_params boot_params __attribute__((aligned(16)));

char *HEAP = _end;
char *heap_end = _end;		/* Default end of heap = no heap */

/*
 * 将头部信息复制到引导参数块中。由于这会破坏旧式命令行协议，因此需要进行调整，改为填写新式命令行指针
 */

static void copy_boot_params(void)
{
	struct old_cmdline {
		u16 cl_magic;
		u16 cl_offset;
	};
	const struct old_cmdline * const oldcmd =
		absolute_pointer(OLD_CL_ADDRESS);

	BUILD_BUG_ON(sizeof(boot_params) != 4096);
	//copy.S
	memcpy(&boot_params.hdr, &hdr, sizeof(hdr));

	if (!boot_params.hdr.cmd_line_ptr &&
	    oldcmd->cl_magic == OLD_CL_MAGIC) {
		/* Old-style command line protocol. */
		u16 cmdline_seg;

		/* Figure out if the command line falls in the region
		   of memory that an old kernel would have copied up
		   to 0x90000... */
		if (oldcmd->cl_offset < boot_params.hdr.setup_move_size)
			cmdline_seg = ds();
		else
			cmdline_seg = 0x9000;

		boot_params.hdr.cmd_line_ptr =
			(cmdline_seg << 4) + oldcmd->cl_offset;
	}
}

/*
 * Query the keyboard lock status as given by the BIOS, and
 * set the keyboard repeat rate to maximum.  Unclear why the latter
 * is done here; this might be possible to kill off as stale code.
 * 调用0x16中断来获取键盘状态
 * 在获取了键盘状态之后，代码再次调用0x16中断来设置键盘的按键检测频率
 */
static void keyboard_init(void)
{
	struct biosregs ireg, oreg;
	initregs(&ireg);

	ireg.ah = 0x02;		/* Get keyboard status */
	intcall(0x16, &ireg, &oreg);
	boot_params.kbd_status = oreg.al;

	ireg.ax = 0x0305;	/* Set keyboard repeat rate */
	intcall(0x16, &ireg, NULL);
}

/*
 * Get Intel SpeedStep (IST) information.
 */
static void query_ist(void)
{
	struct biosregs ireg, oreg;

	/* Some older BIOSes apparently crash on this call, so filter
	   it from machines too old to have SpeedStep at all. */
	if (cpu.level < 6)
		return;

	initregs(&ireg);
	ireg.ax  = 0xe980;	 /* IST Support */
	ireg.edx = 0x47534943;	 /* Request value */
	intcall(0x15, &ireg, &oreg);

	boot_params.ist_info.signature  = oreg.eax;
	boot_params.ist_info.command    = oreg.ebx;
	boot_params.ist_info.event      = oreg.ecx;
	boot_params.ist_info.perf_level = oreg.edx;
}

/*
 * Tell the BIOS what CPU mode we intend to run in.
 */
static void set_bios_mode(void)
{
#ifdef CONFIG_X86_64
	struct biosregs ireg;

	initregs(&ireg);
	ireg.ax = 0xec00;
	ireg.bx = 2;
	intcall(0x15, &ireg, NULL);
#endif
}

static void init_heap(void)
{
	char *stack_end;

	if (boot_params.hdr.loadflags & CAN_USE_HEAP) {
		//计算堆栈结束地址 stack_end = esp - STACK_SIZE
		asm("leal %P1(%%esp),%0"
		    : "=r" (stack_end) : "i" (-STACK_SIZE));
		//计算堆结束地址
		heap_end = (char *)
			((size_t)boot_params.hdr.heap_end_ptr + 0x200);
		//全局堆和堆栈是相邻的，但是增长方向是相反的
		if (heap_end > stack_end)
			heap_end = stack_end;
	} else {
		/* Boot protocol 2.00 only, no heap available */
		puts("WARNING: Ancient bootloader, some functionality "
		     "may be limited!\n");
	}
}
//main_wangs
void main(void)
{
	/* First, 拷贝内核设置信息到 boot_params 结构的相应字段 */
	copy_boot_params();

	/* 初始化 early-boot 控制台 */
	console_init();
	if (cmdline_find_option_bool("debug"))
		//定义在tty.c
		puts("early console in setup code\n");

	/* 初始化全局堆 */
	init_heap();

	/* 检查CPU */
	if (validate_cpu()) {
		puts("Unable to boot - please use a kernel appropriate "
		     "for your CPU.\n");
		die();
	}

	/* 告诉 BIOS 我们打算运行在哪种 CPU 模式下 */
	set_bios_mode();

	/* 探测物理内存 */
	detect_memory();

	/* 设置键盘的重复速率，并查询锁定键的状态 */
	keyboard_init();

	/* 查询 Intel 动态调整CPU的频率和电压 的功能 */
	query_ist();

	/* Query APM information */
#if defined(CONFIG_APM) || defined(CONFIG_APM_MODULE)
	query_apm_bios();
#endif

	/* 查询磁盘驱动信息 */
#if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)
	query_edd();
#endif

	/* 显示模式初始化 */
	set_video();

	/* 做最后的事情，并启动保护模式 */
	go_to_protected_mode();
}
