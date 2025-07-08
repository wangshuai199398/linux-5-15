/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IRQRETURN_H
#define _LINUX_IRQRETURN_H

/** 中断处理函数的返回值
 * enum irqreturn
 * @IRQ_NONE		表示不是我的中断，不归我管
 * @IRQ_HANDLED		中断通过这个设备被处理
 * @IRQ_WAKE_THREAD	有一个进程正在等待这个中断，中断处理完了，应该唤醒它
 */
enum irqreturn {
	IRQ_NONE		= (0 << 0),
	IRQ_HANDLED		= (1 << 0),
	IRQ_WAKE_THREAD		= (1 << 1),
};

typedef enum irqreturn irqreturn_t;
#define IRQ_RETVAL(x)	((x) ? IRQ_HANDLED : IRQ_NONE)

#endif
