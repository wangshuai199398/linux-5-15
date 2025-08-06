.. SPDX-License-Identifier: GPL-2.0
.. include:: <isonum.txt>

==========================
The MSI Driver Guide HOWTO
==========================

:Authors: Tom L Nguyen; Martine Silbermann; Matthew Wilcox

:Copyright: 2003, 2008 Intel Corporation

About this guide
================

本指南介绍了消息信号中断（MSI，Message Signaled Interrupts）的基础知识，包括：
	• 与传统中断机制相比，使用 MSI 的优势，
	• 如何修改驱动程序以支持 MSI 或 MSI-X，
	• 以及在设备不支持 MSI 时可尝试的一些基本诊断方法。


What are MSIs?
==============

消息信号中断（MSI，Message Signaled Interrupt）是指设备向一个特殊地址执行写操作，从而使 CPU 接收到一个中断。

MSI 功能最初在 PCI 2.2 中被定义，在 PCI 3.0 中得到增强，允许对每个中断进行单独屏蔽（mask）。
MSI-X 功能也是在 PCI 3.0 中引入的。
与 MSI 相比，MSI-X 支持每个设备更多的中断数量，并允许对每个中断进行独立配置。

设备可能同时支持 MSI 和 MSI-X，但在同一时间只能启用其中一种。


Why use MSIs?
=============

使用 MSI 相较于传统的基于引脚的中断有三个主要优势：

1. 中断不会被共享，避免性能降低：
   基于引脚（Pin-based）的 PCI 中断通常会在多个设备之间共享。
   为支持共享机制，内核必须调用与该中断相关的所有中断处理程序，这会降低整个系统的性能。
   而 MSI 是永远不会共享的，因此不存在这个问题。

2. 中断顺序更可靠，无需额外确认数据完整性
   当一个设备先将数据写入内存，然后再通过基于引脚的中断通知 CPU，有可能中断会先于数据写入内存完成而被 CPU 接收（在 PCI-PCI 桥后面的设备中这种情况更常见）。
   为确保数据确实已写入内存，中断处理程序通常需要读取产生中断的设备的一个寄存器。
   根据 PCI 的事务顺序规则，在读取该寄存器之前，所有的数据写入必须完成。
   但使用 MSI 时，由于产生中断的写操作不能超过前面的数据写操作，所以当 MSI 到达时，驱动可以确信所有数据已经到达内存，无需额外的同步步骤。

 3.	支持多个中断源，提升中断处理效率：
   PCI 设备每个功能（Function）只能支持一个基于引脚的中断。
   许多驱动因此需要查询设备来判断是哪种事件触发了中断，这会增加常见情况下的中断处理时间。
   而 MSI 支持多个中断，每个中断可以绑定到不同的事件。
   例如，可以将罕见事件（如错误）分配到独立的中断，这样正常事件的处理路径就可以更简洁高效。
   其他设计可能包括：网络卡为每个数据包队列分配一个中断，或存储控制器为每个端口分配一个中断。


How to use MSIs
===============

PCI 设备在初始化时默认使用基于引脚（pin-based）的中断。
如果要使用 MSI 或 MSI-X，则需要由设备驱动程序来配置设备。

不过，并不是所有的计算机都能正确支持 MSI。
对于这些不支持 MSI 的系统，下文所描述的 API 会调用失败，设备将继续使用基于引脚的中断。


启用内核对 MSI 的支持
-------------------------------

要支持 MSI 或 MSI-X，内核必须在编译时启用 CONFIG_PCI_MSI 选项。
该选项仅在某些架构上可用，并且可能依赖于其他选项也被启用。
例如，在 x86 架构上，你还必须启用 X86_UP_APIC 或 SMP，才能看到 CONFIG_PCI_MSI 选项。


Using MSI
---------

大多数繁重的工作都由 PCI 层为驱动程序完成。驱动程序只需请求 PCI 层为该设备设置 MSI 功能即可。

若要自动使用 MSI 或 MSI-X 中断向量，请使用以下函数：

  int pci_alloc_irq_vectors(struct pci_dev *dev, unsigned int min_vecs,
		unsigned int max_vecs, unsigned int flags);

该函数为一个 PCI 设备分配最多 max_vecs 个中断向量。它返回分配的向量数量，或返回一个负值表示错误。

如果设备对最小中断向量数量有要求，驱动程序可以通过设置 min_vecs 参数来指定此限制，如果 PCI 核心无法满足该最小值，则会返回 -ENOSPC 错误。

flags 参数用于指定设备和驱动程序可以使用哪种类型的中断（例如：PCI_IRQ_LEGACY、PCI_IRQ_MSI、PCI_IRQ_MSIX）。
也可以使用一个简便的宏 PCI_IRQ_ALL_TYPES 来表示接受任何可用类型的中断。

如果设置了 PCI_IRQ_AFFINITY 标志，pci_alloc_irq_vectors() 将会把中断分布在可用的 CPU 上。

若要获取传递给 request_irq() 和 free_irq() 的 Linux IRQ 编号以及中断向量，请使用以下函数：

  int pci_irq_vector(struct pci_dev *dev, unsigned int nr);

在移除设备之前，应该使用以下函数释放所有已分配的资源：

  void pci_free_irq_vectors(struct pci_dev *dev);

如果一个设备同时支持 MSI-X 和 MSI 功能，该 API 会优先使用 MSI-X 功能。
MSI-X 支持的中断数量范围为 1 到 2048，而 MSI 最多只能支持 32 个中断，并且必须是 2 的幂。
此外，MSI 的中断向量必须是连续分配的，因此系统可能无法像 MSI-X 那样分配那么多的向量。

在某些平台上，所有 MSI 中断必须被定向到同一组 CPU，而 MSI-X 中断则可以被定向到不同的 CPU。

如果设备既不支持 MSI-X，也不支持 MSI，那么将回退使用单个传统（legacy）IRQ 向量。

使用 MSI 或 MSI-X 中断的一般做法是分配尽可能多的向量，通常是设备所支持的最大值。
如果请求的向量数 nvec 超过设备支持的数量，它将自动被限制为设备所支持的最大值，因此无需提前查询设备支持的中断向量数量：

	nvec = pci_alloc_irq_vectors(pdev, 1, nvec, PCI_IRQ_ALL_TYPES)
	if (nvec < 0)
		goto out_err;

如果驱动程序无法或不愿处理可变数量的 MSI 中断，它可以通过将所需的中断数同时作为 min_vecs 和 max_vecs 参数传递给 pci_alloc_irq_vectors() 函数，从而请求一个固定数量的中断向量：

	ret = pci_alloc_irq_vectors(pdev, nvec, nvec, PCI_IRQ_ALL_TYPES);
	if (ret < 0)
		goto out_err;

上述请求类型中最典型的例子就是为设备启用单个 MSI 模式。
这可以通过将两个 1 分别作为 min_vecs 和 max_vecs 传递来实现：

	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);
	if (ret < 0)
		goto out_err;

某些设备可能不支持使用传统线路中断（legacy line interrupts），
这种情况下，驱动程序可以指定只接受 MSI 或 MSI-X 中断方式：

	nvec = pci_alloc_irq_vectors(pdev, 1, nvec, PCI_IRQ_MSI | PCI_IRQ_MSIX);
	if (nvec < 0)
		goto out_err;

Legacy APIs
-----------

以下用于启用和禁用 MSI 或 MSI-X 中断的旧 API 不应在新代码中使用：

  pci_enable_msi()		/* deprecated */
  pci_disable_msi()		/* deprecated */
  pci_enable_msix_range()	/* deprecated */
  pci_enable_msix_exact()	/* deprecated */
  pci_disable_msix()		/* deprecated */

此外，还有用于获取支持的 MSI 或 MSI-X 向量数量的 API：
pci_msi_vec_count() 和 pci_msix_vec_count()。
通常应避免使用这些函数，建议直接使用 pci_alloc_irq_vectors() 来自动限制分配的中断向量数量。

如果你确实有合法的特殊用例需要获取中断向量的数量，我们也许可以重新考虑这个问题，并添加一个 pci_nr_irq_vectors()辅助函数，用于透明地处理 MSI 和 MSI-X。


Considerations when using MSIs
------------------------------

Spinlocks
~~~~~~~~~

大多数设备驱动程序在中断处理程序中都有一个按设备分配的自旋锁（spinlock）。
对于基于引脚（pin-based）的中断或单个 MSI，中断期间无需显式关闭中断（因为 Linux 保证同一个中断不会被重入）。
但如果设备使用了多个中断通道，驱动程序在持有该锁的同时必须关闭中断。

否则，如果设备在此期间发送了另一个中断，中断处理程序会尝试再次获取这个自旋锁，从而导致死锁。

为避免这种死锁，建议使用 spin_lock_irqsave() 或 spin_lock_irq()，这两个函数会在获取锁的同时禁用本地中断。

详见文档：Documentation/kernel-hacking/locking.rst。


如何判断设备是否启用了 MSI/MSI-X：
----------------------------------------------------

使用 lspci -v（以 root 身份）命令可以查看某些设备是否具有 “MSI”、“Message Signalled Interrupts” 或 “MSI-X” 功能。
这些功能项中都有一个 Enable 标志，其后会显示 “+”（表示已启用）或 “-”（表示未启用）。


MSI quirks
==========

一些 PCI 芯片组或设备已知不支持 MSI。 PCI 子系统提供了三种禁用 MSI 的方式：

1. 全局禁用
2. 禁用某个特定桥接器后面的所有设备的 MSI
3. 禁用单个设备的 MSI

全局禁用 MSI
-----------------------

某些主机芯片组并不能正确支持 MSI。
如果运气好，制造商已经意识到这一问题，并在 ACPI 的 FADT 表中进行了标注。
在这种情况下，Linux 会自动禁用 MSI。

但也有一些主板在该表中没有包含这些信息，因此我们必须自行检测它们。
完整的相关主板列表可在内核源码中的 drivers/pci/quirks.c 文件的 quirk_disable_all_msi() 函数附近找到。

如果你的主板在使用 MSI 时出现问题，可以在内核启动参数中添加 pci=nomsi 来禁用所有设备上的 MSI。
我们强烈建议你将该问题报告给开发社区（发送至 linux-pci@vger.kernel.org），并附上完整的 lspci -v 输出，以便我们将该硬件的特殊情况（quirk）加入内核中。


Disabling MSIs below a bridge
-----------------------------

在桥接设备下禁用 MSI（消息信号中断）：

某些 PCI 桥接器（Bridge）后连接的所有设备可能都会存在 MSI 问题。
为了解决这种情况，可以选择在特定桥接器下禁用 MSI，而不是禁用整个系统中的 MSI。

这种方式可以更细粒度地控制哪些设备启用或禁用 MSI，避免对整个系统造成性能影响，同时绕过不兼容桥接器带来的问题。

       echo 1 > /sys/bus/pci/devices/$bridge/msi_bus

其中，$bridge 是你要设置的桥设备的 PCI 地址（例如：0000:00:0e.0）

如果你想禁用 MSI，而不是启用它，那么将 1 改为 0 即可。
请谨慎修改这个值，因为这可能会破坏该桥接器下所有设备的中断处理功能。

同样地，如果你发现某个桥接器需要特殊处理，请将相关信息（包括详细情况）报告到：


禁用单个设备的 MSI
---------------------------------

一些设备已知其 MSI 实现存在缺陷。通常，这种问题会在对应的设备驱动程序中进行处理，但偶尔也需要通过 “quirk（特殊处理）” 机制解决。
部分驱动程序提供了禁用 MSI 的选项。
虽然这对驱动开发者而言是一个方便的变通方案，但从实践角度来看，这并不是一个好的做法，也不应被模仿。


查找某个设备为何未启用 MSI 的方法
-----------------------------------------

从上面三个部分可以看出，设备未启用 MSI 的原因可能有很多。
你应该首先认真检查 dmesg 输出，判断系统是否启用了 MSI。
你还应检查内核配置 .config 文件，确认已启用 CONFIG_PCI_MSI 选项。

此外，执行 lspci -t 可查看该设备上方的所有 PCI 桥接器。
然后读取对应路径下的 /sys/bus/pci/devices/*/msi_bus 文件，可查看 MSI 是否被启用：
  • 值为 1 表示启用了 MSI
  • 值为 0 表示 MSI 被禁用

如果在从 PCI 根设备到目标设备路径中的任意桥接器的 msi_bus 文件中发现值为 0，则说明该路径上已禁用 MSI，目标设备因此无法使用 MSI。

另外，也值得检查设备驱动程序是否支持 MSI。你可以查看驱动代码是否调用了 pci_alloc_irq_vectors() 函数，并使用了 PCI_IRQ_MSI 或 PCI_IRQ_MSIX 参数标志。
