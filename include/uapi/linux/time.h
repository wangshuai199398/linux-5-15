/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_TIME_H
#define _UAPI_LINUX_TIME_H

#include <linux/types.h>
#include <linux/time_types.h>

#ifndef __KERNEL__
#ifndef _STRUCT_TIMESPEC
#define _STRUCT_TIMESPEC
struct timespec {
	__kernel_old_time_t	tv_sec;		/* seconds */
	long			tv_nsec;	/* nanoseconds */
};
#endif

struct timeval {
	__kernel_old_time_t	tv_sec;		/* seconds */
	__kernel_suseconds_t	tv_usec;	/* microseconds */
};

struct itimerspec {
	struct timespec it_interval;/* timer period */
	struct timespec it_value;	/* timer expiration */
};

struct itimerval {
	struct timeval it_interval;/* timer interval */
	struct timeval it_value;	/* current value */
};
#endif

struct timezone {
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	/* type of dst correction */
};

/*
 * Names of the interval timers, and structure
 * defining a timer setting:
 */
#define	ITIMER_REAL		0
#define	ITIMER_VIRTUAL		1
#define	ITIMER_PROF		2

/*
 * The IDs of the various system clocks (for POSIX.1b interval timers):
 */
// 系统范围内的实时时钟（wall-clock time）
#define CLOCK_REALTIME			0
// 从某个未指定时间点开始的单调时间
#define CLOCK_MONOTONIC			1
// 表示某个进程的所有线程所消耗的 CPU 时间
#define CLOCK_PROCESS_CPUTIME_ID	2
// 表示某个线程特定的 CPU 时间
#define CLOCK_THREAD_CPUTIME_ID		3
// 与 CLOCK_MONOTONIC 类似，但不受 NTP 校准影响
#define CLOCK_MONOTONIC_RAW		4
#define CLOCK_REALTIME_COARSE		5
// CLOCK_MONOTONIC 的更快版本
#define CLOCK_MONOTONIC_COARSE		6
// 与 CLOCK_MONOTONIC 类似，但包括系统挂起的时间
#define CLOCK_BOOTTIME			7
#define CLOCK_REALTIME_ALARM		8
#define CLOCK_BOOTTIME_ALARM		9
/*
 * The driver implementing this got removed. The clock ID is kept as a
 * place holder. Do not reuse!
 */
#define CLOCK_SGI_CYCLE			10
#define CLOCK_TAI			11

#define MAX_CLOCKS			16
#define CLOCKS_MASK			(CLOCK_REALTIME | CLOCK_MONOTONIC)
#define CLOCKS_MONO			CLOCK_MONOTONIC

/*
 * The various flags for setting POSIX.1b interval timers:
 */
#define TIMER_ABSTIME			0x01

#endif /* _UAPI_LINUX_TIME_H */
