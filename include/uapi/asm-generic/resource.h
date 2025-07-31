/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_GENERIC_RESOURCE_H
#define _UAPI_ASM_GENERIC_RESOURCE_H

/*
 * Resource limit IDs
 *
 * ( Compatibility detail: there are architectures that have
 *   a different rlimit ID order in the 5-9 range and want
 *   to keep that order for binary compatibility. The reasons
 *   are historic and all new rlimits are identical across all
 *   arches. If an arch has such special order for some rlimits
 *   then it defines them prior including asm-generic/resource.h. )
 */

#define RLIMIT_CPU		0	/* 进程可使用的最大 CPU 时间（秒）*/
#define RLIMIT_FSIZE		1	/* 可以创建的最大文件大小（字节）*/
#define RLIMIT_DATA		2	/* 数据段的最大大小 */
#define RLIMIT_STACK		3	/* 栈的最大大小 */
#define RLIMIT_CORE		4	/* core 文件的最大大小 */

#ifndef RLIMIT_RSS
# define RLIMIT_RSS		5	/* 进程可占用的最大常驻集内存大小 */
#endif

#ifndef RLIMIT_NPROC
//用户所能拥有的最大进程数
# define RLIMIT_NPROC		6	/* 用户可拥有的最大进程数 */
#endif

#ifndef RLIMIT_NOFILE
# define RLIMIT_NOFILE		7	/* 一个进程可打开的最大文件描述符数量 */
#endif

#ifndef RLIMIT_MEMLOCK
# define RLIMIT_MEMLOCK		8	/* 可以锁定在内存中的最大字节数 */
#endif

#ifndef RLIMIT_AS
# define RLIMIT_AS		9	/* 进程可使用的最大虚拟内存空间 */
#endif

#define RLIMIT_LOCKS		10	/* 最大文件锁数量 */
//用户所能拥有的最大挂起信号数
#define RLIMIT_SIGPENDING	11	/* 一个用户可以挂起的信号数量上限 */
#define RLIMIT_MSGQUEUE		12	/* POSIX 消息队列可使用的最大字节数 */
#define RLIMIT_NICE		13	/* 可以设置的最大 nice 值 allowed to raise to 0-39 for nice level 19 .. -20 */
#define RLIMIT_RTPRIO		14	/* 可用的最大实时优先级 */
#define RLIMIT_RTTIME		15	/* 实时调度线程允许运行的最大时间（微秒）*/
#define RLIM_NLIMITS		16

/*
 * SuS says limits have to be unsigned.
 * Which makes a ton more sense anyway.
 *
 * Some architectures override this (for compatibility reasons):
 */
#ifndef RLIM_INFINITY
# define RLIM_INFINITY		(~0UL)
#endif


#endif /* _UAPI_ASM_GENERIC_RESOURCE_H */
