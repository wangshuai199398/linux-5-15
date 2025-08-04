/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__ASM_GENERIC_SIGNAL_H
#define _UAPI__ASM_GENERIC_SIGNAL_H

#include <linux/types.h>

#define _NSIG		64
#define _NSIG_BPW	__BITS_PER_LONG
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

// 挂起 signal_wangs
#define SIGHUP		 1
// 终端中断
#define SIGINT		 2
// 终端退出
#define SIGQUIT		 3
// 无效命令
#define SIGILL		 4
// 跟踪陷阱
#define SIGTRAP		 5
#define SIGABRT		 6
// IOT 陷阱
#define SIGIOT		 6
// BUS 错误
#define SIGBUS		 7
// 浮点异常
#define SIGFPE		 8
// 强行终止，不能被捕获或忽略
#define SIGKILL		 9
// 用户定义的信号1
#define SIGUSR1		10
// 无效的内存段处理
#define SIGSEGV		11
// 用户定义的信号2
#define SIGUSR2		12
// 半关闭管道的写操作已经发生
#define SIGPIPE		13
// 计时器到期
#define SIGALRM		14
// 终止
#define SIGTERM		15
// 堆栈错误
#define SIGSTKFLT	16
// 子进程已经停止或退出
#define SIGCHLD		17
// 如果停止了，继续执行
#define SIGCONT		18
// 停止执行，不能被捕获或忽略
#define SIGSTOP		19
// 终端停止信号
#define SIGTSTP		20
// 后台进行需要从终端读取输入
#define SIGTTIN		21
// 后台进行需要从终端写出
#define SIGTTOU		22
// 紧急的套接字事件
#define SIGURG		23
// 超额使用 CPU 分配的时间
#define SIGXCPU		24
// 文件尺寸超额
#define SIGXFSZ		25
// 虚拟时钟信号
#define SIGVTALRM	26
// 时钟信号描述
#define SIGPROF		27
// 窗口尺寸变化
#define SIGWINCH	28
// I/O
#define SIGIO		29
#define SIGPOLL		SIGIO
/*
#define SIGLOST		29
*/
// 断电重启
#define SIGPWR		30
#define SIGSYS		31
#define	SIGUNUSED	31

/* These should not be considered constants from userland.  */
#define SIGRTMIN	32
#ifndef SIGRTMAX
#define SIGRTMAX	_NSIG
#endif

#if !defined MINSIGSTKSZ || !defined SIGSTKSZ
#define MINSIGSTKSZ	2048
#define SIGSTKSZ	8192
#endif

#ifndef __ASSEMBLY__
typedef struct {
	unsigned long sig[_NSIG_WORDS];
} sigset_t;

/* not actually used, but required for linux/syscalls.h */
typedef unsigned long old_sigset_t;

#include <asm-generic/signal-defs.h>

#ifdef SA_RESTORER
#define __ARCH_HAS_SA_RESTORER
#endif

#ifndef __KERNEL__
struct sigaction {
	__sighandler_t sa_handler;
	unsigned long sa_flags;
#ifdef SA_RESTORER
	__sigrestore_t sa_restorer;
#endif
	sigset_t sa_mask;		/* mask last for extensibility */
};
#endif

typedef struct sigaltstack {
	void __user *ss_sp;
	int ss_flags;
	size_t ss_size;
} stack_t;

#endif /* __ASSEMBLY__ */

#endif /* _UAPI__ASM_GENERIC_SIGNAL_H */
