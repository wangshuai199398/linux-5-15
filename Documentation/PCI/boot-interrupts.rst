.. SPDX-License-Identifier: GPL-2.0

===============
Boot Interrupts
===============

:Author: - Sean V Kelley <sean.v.kelley@linux.intel.com>

Overview
========

在 PCI Express 中，中断通过 MSI 或入带中断消息（Assert_INTx / Deassert_INTx）表示。
某些 Core IO 中集成的 IO-APIC（I/O 高级可编程中断控制器）会将来自 PCI Express 的传统中断消息转换为 MSI 中断。

如果 IO-APIC 被禁用（通过 IO-APIC 表项中的屏蔽位），这些消息将被路由到传统的 PCH（平台控制器集线器）。
这种入带中断机制最初是为不支持 IO-APIC 的系统和系统启动过程而设计的。

英特尔过去称这一机制为“启动中断（boot interrupts）”。此外，PCI Express 协议将这种入带的传统线路中断 INTx 机制描述为 I/O 设备用来发出 PCI 风格电平中断的一种方式。

接下来的段落将描述 Core IO 在将 INTx 消息路由到 PCH 时存在的问题，以及 BIOS 和操作系统中为缓解这些问题所采取的措施。


Issue
=====

当入带的传统 INTx 消息被转发至 PCH（平台控制器集线器）时，它们会触发一个新的中断，而操作系统往往没有为此中断设置处理程序（handler）。

如果一个中断长时间无人处理，Linux 内核会将其标记为伪中断（Spurious Interrupt）。
当该中断的未处理次数达到一定数量后，Linux 内核会禁用该 IRQ，并显示错误信息 “nobody cared”。

一旦该 IRQ 被禁用，就会阻止任何有效的中断使用该中断号，这对于可能共享这条 IRQ 线路的设备来说是致命的。例如：

  irq 19: nobody cared (try booting with the "irqpoll" option)
  CPU: 0 PID: 2988 Comm: irq/34-nipalk Tainted: 4.14.87-rt49-02410-g4a640ec-dirty #1
  Hardware name: National Instruments NI PXIe-8880/NI PXIe-8880, BIOS 2.1.5f1 01/09/2020
  Call Trace:

  <IRQ>
   ? dump_stack+0x46/0x5e
   ? __report_bad_irq+0x2e/0xb0
   ? note_interrupt+0x242/0x290
   ? nNIKAL100_memoryRead16+0x8/0x10 [nikal]
   ? handle_irq_event_percpu+0x55/0x70
   ? handle_irq_event+0x4f/0x80
   ? handle_fasteoi_irq+0x81/0x180
   ? handle_irq+0x1c/0x30
   ? do_IRQ+0x41/0xd0
   ? common_interrupt+0x84/0x84
  </IRQ>

  handlers:
  irq_default_primary_handler threaded usb_hcd_irq
  Disabling IRQ #19
  这个例子中，IRQ 19 被禁用了，意味着所有共享该中断线的设备将无法继续正常工作。系统日志建议尝试使用 irqpoll 内核参数来继续引导系统。


Conditions
==========

在当前系统中，线程化中断（threaded interrupts） 是最可能触发该问题的条件。
线程化中断在中断处理程序唤醒后，可能不会重新启用 IRQ（中断请求）。
这些所谓的“一次性（one shot）”条件要求线程化中断在其处理线程运行完毕前保持中断线路处于屏蔽状态（masked）。

尤其是在处理高数据速率中断时，中断线程必须运行完成，否则可能会因中断设备持续发出中断而导致处理线程出现**栈溢出（stack overflow）**等问题。


Affected Chipsets
=================

传统的中断转发机制（legacy interrupt forwarding）如今依然存在于多种设备中，包括但不限于以下厂商的芯片组：
   • AMD/ATI
   • Broadcom
   • Intel

对此问题的缓解措施已经通过补丁集成到了内核代码的 drivers/pci/quirks.c 文件中。

自 英特尔 Ice Lake Xeon（ICX） 起，Core IO 设备中已不再包含 IO-APIC，IO-APIC 仅保留在 PCH（平台控制器集线器）中。
连接到 Core IO 的 PCIe 根端口（Root Ports）的设备将使用原生的 MSI/MSI-X 中断机制，而不再依赖传统中断转发方式。

Mitigations
===========

这些缓解措施采用了 PCI quirks（特殊处理机制）的形式。
优先选择的方法是首先识别并利用某种手段来禁用到 PCH 的中断路由。在这种情况下，可以添加一个 quirk 来禁用启动中断的生成。[1]_

Intel® 6300ESB I/O Controller Hub
  Alternate Base Address Register:
   BIE: Boot Interrupt Enable

	  ==  ===========================
	  0   Boot interrupt is enabled.
	  1   Boot interrupt is disabled.
	  ==  ===========================

Intel® Sandy Bridge through Sky Lake based Xeon servers:
  Coherent Interface Protocol Interrupt Control
   dis_intx_route2pch/dis_intx_route2ich/dis_intx_route2dmi2:
	  When this bit is set. Local INTx messages received from the
	  Intel® Quick Data DMA/PCI Express ports are not routed to legacy
	  PCH - they are either converted into MSI via the integrated IO-APIC
	  (if the IO-APIC mask bit is clear in the appropriate entries)
	  or cause no further action (when mask bit is set)

在无法直接禁用中断路由的情况下，另一种方法是利用 PCI 中断引脚到 INTx 路由表，将中断处理程序默认重定向到被重新路由的中断线。

因此，在 无法禁用 INTx 路由的芯片组上，Linux 内核会将有效的中断重定向到其传统中断上。
这种中断处理程序的重定向可以防止“虚假中断（spurious interrupt）”的检测，
避免因为未处理中断次数过多而被禁用 IRQ 线路的情况发生。[2]_

内核配置选项 X86_REROUTE_FOR_BROKEN_BOOT_IRQS 允许启用或禁用将中断处理程序重定向到 PCH 中断线的机制。
该选项也可以通过以下引导参数覆盖：
  • 启用：pci=ioapicreroute
  • 禁用：pci=noioapicreroute【3】


More Documentation
==================

以下数据手册中提供了对传统中断（Legacy Interrupt）处理的概述（如 6300ESB 和 6700PXH）。
虽然处理方式大体相同，但这些内容有助于了解不同芯片组中断处理机制的演进过程。

Example of disabling of the boot interrupt
------------------------------------------

      - Intel® 6300ESB I/O Controller Hub (Document # 300641-004US)
	5.7.3 Boot Interrupt
	https://www.intel.com/content/dam/doc/datasheet/6300esb-io-controller-hub-datasheet.pdf

      - Intel® Xeon® Processor E5-1600/2400/2600/4600 v3 Product Families
	Datasheet - Volume 2: Registers (Document # 330784-003)
	6.6.41 cipintrc Coherent Interface Protocol Interrupt Control
	https://www.intel.com/content/dam/www/public/us/en/documents/datasheets/xeon-e5-v3-datasheet-vol-2.pdf

Example of handler rerouting
----------------------------

      - Intel® 6700PXH 64-bit PCI Hub (Document # 302628)
	2.15.2 PCI Express Legacy INTx Support and Boot Interrupt
	https://www.intel.com/content/dam/doc/datasheet/6700pxh-64-bit-pci-hub-datasheet.pdf


If you have any legacy PCI interrupt questions that aren't answered, email me.

Cheers,
    Sean V Kelley
    sean.v.kelley@linux.intel.com

.. [1] https://lore.kernel.org/r/12131949181903-git-send-email-sassmann@suse.de/
.. [2] https://lore.kernel.org/r/12131949182094-git-send-email-sassmann@suse.de/
.. [3] https://lore.kernel.org/r/487C8EA7.6020205@suse.de/
