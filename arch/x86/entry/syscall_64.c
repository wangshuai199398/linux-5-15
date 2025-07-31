// SPDX-License-Identifier: GPL-2.0
/* System call table for x86-64. */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <linux/syscalls.h>
#include <asm/syscall.h>

#define __SYSCALL(nr, sym) extern long __x64_##sym(const struct pt_regs *);
#include <asm/syscalls_64.h>
#undef __SYSCALL

/*
 * The sys_call_table[] is no longer used for system calls, but
 * kernel/trace/trace_syscalls.c still wants to know the system
 * call address.
 * sys_call_table_wangs
 */
/*
asmlinkage const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
	[0 ... __NR_syscall_max] = &sys_ni_syscall,
	[0] = sys_read,
	[1] = sys_write,
	[2] = sys_open,
	...
	...
	...
};
*/
#define __SYSCALL(nr, sym) __x64_##sym,
const sys_call_ptr_t sys_call_table[] = {
#include <asm/syscalls_64.h>
};
#undef __SYSCALL

#define __SYSCALL(nr, sym) case nr: return __x64_##sym(regs);
//基于系统调用号 nr 的系统调用分发器（dispatcher）
long x64_sys_call(const struct pt_regs *regs, unsigned int nr)
{
	switch (nr) {
	#include <asm/syscalls_64.h>
	default: return __x64_sys_ni_syscall(regs);
	}
};
