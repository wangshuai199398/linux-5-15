// SPDX-License-Identifier: GPL-2.0
/*
 * Support routines for initializing a PCI subsystem
 *
 * Extruded from code written by
 *      Dave Rusling (david.rusling@reo.mts.dec.com)
 *      David Mosberger (davidm@cs.arizona.edu)
 *	David Miller (davem@redhat.com)
 */


#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/cache.h>
#include "pci.h"

void pci_assign_irq(struct pci_dev *dev)
{
	u8 pin;
	u8 slot = -1;
	int irq = 0;
    //获取PCI主机桥结构体，主机桥是连接 CPU 总线和 PCI 总线的硬件
	struct pci_host_bridge *hbrg = pci_find_host_bridge(dev->bus);

	if (!(hbrg->map_irq)) {
		pci_dbg(dev, "runtime IRQ mapping not provided by arch\n");//
		return;
	}

	/* If this device is not on the primary bus, we need to figure out
	   which interrupt pin it will come in on.   We know which slot it
	   will come in on 'cos that slot is where the bridge is.   Each
	   time the interrupt line passes through a PCI-PCI bridge we must
	   apply the swizzle function.  */
	//读取 PCI 配置空间中的 PCI_INTERRUPT_PIN 字段，指示该 PCI 设备使用的是哪个中断引脚。PCI 设备有 4 个中断引脚（A、B、C、D），用来连接到中断控制器
	pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &pin);
	/* Cope with illegal. */
	if (pin > 4)
		pin = 1;

	if (pin) {
		/* Follow the chain of bridges, swizzling as we go.  
		   swizzle_irq处理跨多个 PCI 总线或桥接设备时的中断重新映射
		   调用它来计算该设备的 slot。这个 slot 表示设备所处的插槽，可能经过 “swizzle”（中断重排）操作后发生变化*/
		if (hbrg->swizzle_irq)
			slot = (*(hbrg->swizzle_irq))(dev, &pin);

		/*
		 * If a swizzling function is not used map_irq must ignore slot
		 * 将设备、插槽和中断引脚映射到一个具体的 IRQ 号
		 */
		irq = (*(hbrg->map_irq))(dev, slot, pin);
		if (irq == -1)
			irq = 0;
	}
	dev->irq = irq;

	pci_dbg(dev, "assign IRQ: got %d\n", dev->irq);

	/* Always tell the device, so the driver knows what is
	   the real IRQ to use; the device does not use it. */
	pci_write_config_byte(dev, PCI_INTERRUPT_LINE, irq);
}
