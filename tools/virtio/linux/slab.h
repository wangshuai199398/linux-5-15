/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_SLAB_H
//普通内核上下文内存分配,允许睡眠，系统调用、线程上下文
#define GFP_KERNEL 0
//Get Free Page 高优先级、不可睡眠（non-blocking）的内存分配请求,用于 中断处理上下文、软中断上下文 或 spinlock 等锁保护的临界区中，这些地方 不能睡眠（不能调用调度器），所以必须立即返回
//如果你马上有空闲内存，就给我；如果没有，也不要等，直接失败返回 NULL
#define GFP_ATOMIC 0
#define __GFP_NOWARN 0
#define __GFP_ZERO 0
#endif
