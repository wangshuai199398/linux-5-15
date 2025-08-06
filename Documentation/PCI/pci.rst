.. SPDX-License-Identifier: GPL-2.0

==============================
How To Write Linux PCI Drivers
==============================

:Authors: - Martin Mares <mj@ucw.cz>
          - Grant Grundler <grundler@parisc-linux.org>

PCI 的世界广阔而充满了（大多令人头疼的）惊喜。
由于每种 CPU 架构都实现了不同的芯片组，而 PCI 设备又有各种各样的需求（呃，称为“特性”），
所以 Linux 内核中的 PCI 支持并不像人们希望的那样简单。

这篇简短的文档旨在为潜在的驱动开发者介绍 Linux 中 PCI 设备驱动的 API。

一个更全面的参考资源是由 Jonathan Corbet、Alessandro Rubini 和 Greg Kroah-Hartman 合著的
《Linux 设备驱动程序(第三版)》(Linux Device Drivers, Third Edition)

该书可以在以下地址免费下载（遵循 Creative Commons 许可）：

https://lwn.net/Kernel/LDD3/

不过, 请记住: 所有文档都可能会“信息腐烂”(bit rot)。
如果你发现文中描述无法正常工作，请直接参考源代码。


PCI 驱动的结构
========================

PCI 驱动程序是通过调用 pci_register_driver() 来“发现”系统中的 PCI 设备的。
实际上，流程是反过来的：当 PCI 通用层(generic code)发现一个新设备时, 会通知与其匹配描述信息的驱动程序。
详细说明请见下文

pci_register_driver() 会将大部分设备探测工作交由 PCI 层处理，并支持设备的在线插入/移除，
因此能够在一个驱动程序中同时支持 热插拔 PCI、CardBus 以及 Express-Card。
调用 pci_register_driver() 时需要传入一个函数指针表，因此也就规定了驱动程序的高层结构。

一旦驱动程序识别并“接管”了一个 PCI 设备，它通常需要执行以下初始化步骤：

  - 启用设备
  - 申请 MMIO(内存映射 I/O)/IOP(I/O 端口)资源
  - 设置 DMA 掩码大小(用于 coherent DMA 和 streaming DMA)
  - 分配并初始化共享控制数据(使用 pci_allocate_coherent())
  - 访问设备配置空间(如有需要)
  - 注册中断处理程序(使用 request_irq())
  - 初始化非 PCI 部分(例如芯片的 LAN / SCSI 等模块)
  - 启用 DMA 处理引擎

当设备使用完毕，或者需要卸载模块时，驱动程序需要执行以下步骤：

  - 禁用设备产生中断(IRQs)
  - 释放中断资源(free_irq())
  - 停止所有 DMA 活动
  - 释放 DMA 缓冲区（包括 streaming 和 coherent 类型）
  - 从其他子系统注销(例如 SCSI 或 netdev)
  - 释放 MMIO / IOP 资源
  - 禁用设备

这些主题中的大多数将在接下来的章节中进行介绍。
其余内容请参考《LDD3》或 <linux/pci.h> 文件

如果未配置 PCI 子系统(即未设置 CONFIG_PCI), 那么下文中描述的大多数 PCI 函数将被定义为内联函数(inline functions),
这些函数要么是完全空实现，要么只是返回相应的错误码, 以此来避免在驱动代码中大量使用 #ifdef 条件编译


pci_register_driver() call
==========================

PCI 设备驱动程序在初始化过程中会调用 pci_register_driver(), 并传入一个指向**描述该驱动的结构体(struct pci_driver)的指针:

.. kernel-doc:: include/linux/pci.h
   :functions: pci_driver

ID 表是一个由多个 ``struct pci_device_id`` 条目组成的数组，并以一个全零的条目结尾。
通常推荐使用 static const 进行定义。

.. kernel-doc:: include/linux/mod_devicetable.h
   :functions: pci_device_id

大多数驱动只需要使用 ``PCI_DEVICE()`` 或 ``PCI_DEVICE_CLASS()`` 宏来构建 pci_device_id 表

可以在运行时向设备驱动的 pci_ids 表中添加新的 PCI ID, 方式如下:

  echo "vendor device subvendor subdevice class class_mask driver_data" > \
/sys/bus/pci/drivers/{driver}/new_id

所有字段都以十六进制形式传入 (不带 0x 前缀).
其中, vendor 和 device 字段是必填的，其余字段是可选的. 用于只需提供所需的可选字段即可: 

  - subvendor 和 subdevice 字段默认为 PCI_ANY_ID (FFFFFFFF)
  - class 和 classmask 字段默认为0
  - driver_data defaults to 0UL.
  - override_only 字段默认为0

需要注意的是, 如果驱动中定义的所有 pci_device_id 条目都使用了非零的 driver_data, 那么添加新 ID 时, driver_data 字段也必须提供并匹配驱动已有条目的值

添加成功后, 驱动的 probe 函数会对 pci_ids 列表中所有尚未绑定的设备进行处理

当驱动卸载时, 只需调用 pci_unregister_driver(), PCI 层会自动调用该驱动处理的所有设备的 remove 钩子函数


"Attributes" for driver functions/data
--------------------------------------

请在适当的位置标记初始化函数和清理函数(对应的宏定义在 <linux/init.h> 中)

	======		=================================================
	__init		初始化代码: 在驱动初始化完成后会被丢弃
	__exit		退出代码: 对于非模块化驱动将被忽略。
	======		=================================================

关于何时/何处使用上述属性的提示:
	- module_init() / module_exit() 函数（以及仅由它们调用的所有初始化函数）应标记为 __init / __exit

	- 不要对 struct pci_driver 结构体使用任何标记

	- 如果你不确定使用哪个标记，不要随便添加标记, 与其错误地标记函数，不如干脆不标记


如何手动查找 PCI 设备
================================

PCI 驱动程序应当有充分理由才不使用 pci_register_driver() 接口来查找 PCI 设备。
出现一个 PCI 设备被多个驱动控制的主要原因通常是: 一个 PCI 设备实现了多个硬件功能, 例如：串口 / 并口 / 软驱控制器的组合设备。

可以使用以下方式手动查找设备: 

通过厂商 ID 和设备 ID 查找::

	struct pci_dev *dev = NULL;
	while (dev = pci_get_device(VENDOR_ID, DEVICE_ID, dev))
		configure_device(dev);

通过 class ID 查找 (以类似方式进行迭代)::

	pci_get_class(CLASS_ID, dev)

通过 vendor/device ID 和 subsystem vendor/device ID 查找::

	pci_get_subsys(VENDOR_ID,DEVICE_ID, SUBSYS_VENDOR_ID, SUBSYS_DEVICE_ID, dev).

你可以使用常量 PCI_ANY_ID 作为 VENDOR_ID 或 DEVICE_ID 的通配符, 例如可以用来查找某个特定厂商的所有设备

这些函数是支持热插拔的(hotplug-safe), 它们会自动对返回的 pci_dev 增加引用计数。
你最终必须(例如在模块卸载时)调用 pci_dev_put() 来减少引用计数。


Device Initialization Steps
===========================

如前言所述，大多数 PCI 驱动程序在设备初始化时需要执行以下步骤:

  - 使能设备
  - 申请 MMIO(内存映射I/O)/IOP(I/O端口)资源
  - 设置DMA掩码大小(用于coherent DMA和streaming DMA)
  - 分配并初始化共享控制数据 (使用pci_allocate_coherent())
  - 访问设备配置空间 (如果需要)
  - 注册中断处理函数 (request_irq())
  - 初始化非 PCI 部分 (例如芯片中的 LAN / SCSI 等部分)
  - 启用 DMA / 处理引擎

驱动程序可以在任何时候访问 PCI 配置空间寄存器。(几乎任何时候。当运行 BIST(内建自测试)时，配置空间可能会消失……
但这通常只会导致一次 PCI 总线主控中止(Bus Master Abort),并且配置读取将返回无效数据)


Enable the PCI device
---------------------
在访问任何设备寄存器之前，驱动程序需要通过调用 pci_enable_device() 来启用 PCI 设备。
此操作将会：

  - 如果设备处于挂起状态，将其唤醒
  - 分配设备的 I/O 和内存区域(如果 BIOS 尚未分配)
  - 分配中断请求(IRQ)(如果 BIOS 尚未分配)

.. note::
   pci_enable_device() 可能失败, 检查返回值

.. warning::
   操作系统缺陷(OS BUG): 在启用设备资源之前，我们并不会检查资源是否已被正确分配。
   如果我们在调用 pci_enable_device() 之前先调用 pci_request_resources(), 流程会更合理。
   目前，当两个设备被分配到相同的资源范围时，驱动程序并无法检测出这个问题。
   尽管这种情况较为罕见，但也不太可能在短期内得到修复。

该问题早在 Linux 2.6.19 时就已被讨论，但直到现在仍未更改：
https://lore.kernel.org/r/20060302180025.GC28895@flint.arm.linux.org.uk/


pci_set_master() 通过设置 PCI_COMMAND 寄存器中的总线主控位(bus master bit)来启用 DMA
它还会在BIOS设置了无效的延迟定时器值(latency timer)时自动进行修正
若要禁用 DMA, 可调用 pci_clear_master() 来清除总线控制位

如果 PCI 设备支持 PCI Memory-Write-Invalidate(内存写入失效)事务
可以调用 pci_set_mwi()。该函数会启用 PCI_COMMAND 中的 Mem-Wr-Inval 位，
并确保缓存行大小寄存器(cache line size register)设置正确。

需要注意的是，并非所有架构或芯片组都支持 Memory-Write-Invalidate
因此应检查 pci_set_mwi() 的返回值。

另外，如果 Mem-Wr-Inval 是一个“可有可无”的优化需求，
可以使用 pci_try_set_mwi()，系统会尽力尝试启用该功能（即使不支持也不会报错）


Request MMIO/IOP resources
--------------------------

不能直接从 PCI 设备的配置空间中读取内存（MMIO）或 I/O 端口地址。
应该使用 pci_dev 结构体中的地址值，
因为所谓的 “PCI 总线地址” 可能已经被架构/芯片组相关的内核支持代码重映射为主机物理地址。

关于如何访问设备寄存器或设备内存，请参阅： Documentation/driver-api/io-mapping.rst

驱动程序需要调用 pci_request_region() 来确保没有其他设备正在使用相同的地址资源。
相反，在调用 pci_disable_device() 之后，驱动应调用 pci_release_region() 释放资源。
这么做的目的是防止多个设备使用相同的地址范围发生冲突。

.. tip::
   请参考上文提到的“OS BUG”注释。当前（2.6.19）版本中
   驱动程序只能在调用 pci_enable_device() 之后才能确定
   MMIO 和 IO 端口资源是否可用。

pci_request_region() 的通用形式包括：
	•	request_mem_region()：用于 MMIO（内存映射 I/O）资源范围
	•	request_region()：用于 I/O 端口资源范围

这些函数适用于那些不通过常规 PCI BAR（基地址寄存器）描述的地址资源。

另请参考下面提到的 pci_request_selected_regions()。


Set the DMA mask size
---------------------
.. note::
   如果以下内容有任何不清楚的地方，请参考
   Documentation/core-api/dma-api.rst。
   本节只是提醒驱动程序需要声明设备的 DMA 能力，
   并不是 DMA 接口的权威资料来源

虽然所有驱动程序都应该明确指示 PCI 总线主控设备的 DMA 能力（例如支持 32 位或 64 位），
但如果设备具有 大于 32 位的总线主控 DMA 能力 用于处理流式数据，
驱动程序需要通过调用 pci_set_dma_mask() 并传入合适的参数来“注册”该能力。

一般来说，在物理地址超过 4GB 的系统中，这样可以实现更高效的 DMA 访问。

对于所有符合 PCI-X 和 PCIe 标准 的设备的驱动程序，
必须调用 pci_set_dma_mask()，因为它们属于 64 位 DMA 设备。

同样地，如果设备能够直接访问位于物理地址 4GB 以上的系统内存中用于“一致性内存”（consistent memory） 的区域，
驱动程序还需要调用 pci_set_consistent_dma_mask() 来注册此能力。

这也适用于所有 PCI-X 和 PCIe 兼容设备的驱动程序。

需要注意的是，许多早期的 64 位 “PCI” 设备（在 PCI-X 之前）以及某些 PCI-X 设备，虽然支持 64 位 DMA 传输数据（streaming data），
但不支持控制数据（consistent data）的 64 位 DMA 访问。


Setup shared control data
-------------------------

一旦设置了 DMA 掩码，驱动程序就可以分配“一致性内存”（又称 shared memory，共享内存）。
关于 DMA API 的完整说明，请参阅：
Documentation/core-api/dma-api.rst
本节仅作为提醒：这一操作必须在启用设备的 DMA 功能之前完成


Initialize device registers
---------------------------
某些驱动程序可能需要对特定的“功能（capability）”字段进行编程，或者初始化 / 重置其他“厂商特定（vendor specific）”的寄存器。
例如：清除挂起的中断（pending interrupts）。


Register IRQ handler
--------------------

虽然调用 request_irq() 是此处描述的最后一个步骤，但这通常只是初始化设备的中间步骤之一。
该步骤通常可以推迟到设备被实际打开使用时再执行

所有用于 IRQ 线路的中断处理程序都应使用 IRQF_SHARED 标志注册，
并且应使用 devid 参数将中断请求与设备进行映射（请记住，所有 PCI 的 IRQ 线路都是可共享的）。

request_irq() 会将一个中断处理程序和设备句柄与某个中断号关联起来。
从历史上看，中断号代表的是 PCI 设备到中断控制器之间的物理 IRQ 线路。
但在使用 MSI（Message Signaled Interrupts） 和 MSI-X 的情况下，
中断号代表的是一个 CPU 中断向量（vector）。

此外，request_irq() 还会启用中断。因此在注册中断处理程序之前，
应确保设备已经处于静止（quiesced）状态，并且没有任何挂起中断。

MSI 和 MSI-X 都是 PCI 的一种能力（Capability），
它们通过 DMA 写入 Local APIC 的方式向 CPU 发送中断信号。
两者的主要区别在于如何分配多个“向量”：
	•	MSI：要求分配一块连续的中断向量
	•	MSI-X：可以分配多个不连续的独立向量

你可以在调用 request_irq() 之前，使用如下方式启用 MSI 能力：
  pci_alloc_irq_vectors(dev, min_vecs, max_vecs, PCI_IRQ_MSI | PCI_IRQ_MSIX);
这会让内核在设备的 PCI 配置空间中写入 CPU 的向量信息。
需要注意：许多架构、芯片组或 BIOS 并不支持 MSI 或 MSI-X，
因此调用 pci_alloc_irq_vectors() 时建议始终同时指定 PCI_IRQ_LEGACY，
以便在失败时回退到传统中断模式。

驱动程序如果对 MSI/MSI-X 与传统 INTx 中断有不同的中断处理逻辑，
可以在调用 pci_alloc_irq_vectors() 之后，
根据 pci_dev 结构中的 msi_enabled 和 msix_enabled 标志来选择合适的处理函数。

使用 MSI 至少有两个非常重要的好处：

1) MSI 是一种天生“独占”的中断向量（exclusive interrupt vector）。
   这意味着中断处理程序不需要再判断是否是自己的设备引发了中断。

2) MSI 能避免 DMA 与中断（IRQ）之间的竞争条件（race conditions）。
   当 MSI 中断被发送时，DMA 写入主机内存的数据会被保证对 CPU 可见。
   这对于数据一致性以及避免读取过时控制数据非常重要。
   在这种机制下，驱动程序可以省略用于刷新 DMA 流的 MMIO 读操作。

See drivers/infiniband/hw/mthca/ or drivers/net/tg3.c for examples
of MSI/MSI-X usage.


PCI device shutdown
===================

当卸载一个 PCI 设备驱动程序时，通常需要执行以下步骤：

	•	禁用设备的中断（防止其继续产生 IRQ）
	•	释放中断资源（调用 free_irq()）
	•	停止所有的 DMA 活动
	•	释放 DMA 缓冲区（包括 streaming 和 consistent 类型）
	•	从其他子系统中注销（例如 SCSI 或网络子系统）
	•	禁用设备对 MMIO / IO 端口地址的响应
	•	释放 MMIO / IO 端口资源


Stop IRQs on the device
-----------------------

如何执行这些操作取决于具体的芯片或设备。如果不正确处理，在 IRQ 被多个设备共享的情况下，可能会导致所谓的“尖叫中断（screaming interrupt）”。

当共享中断处理程序被“解除挂接”（unhooked）时，使用同一中断线的其他设备仍然需要该中断继续启用。
如果此时已解除挂接的设备继续拉高中断线，系统会误以为是其他设备触发了中断。

由于没有任何一个剩余设备会处理这个中断，系统将会一直等待，
直到它判断该中断不会被处理为止（大约等待 100,000 次迭代），最终屏蔽该中断线。

一旦共享的中断被屏蔽，所有使用该中断线的设备都将无法正常工作——这将是一个非常糟糕的情况。

这也是建议在可能的情况下使用 MSI 或 MSI-X 的另一个原因。
MSI 和 MSI-X 都是“独占中断”，因此不会受到“尖叫中断”问题的影响。

Release the IRQ
---------------
一旦设备被静默处理（即不再产生中断），就可以调用 free_irq()。
该函数在完成以下操作后会返回：
	•	等待并处理所有仍在排队中的中断请求（IRQ）；
	•	将驱动程序的中断处理程序从该中断号上解除挂接；
	•	如果没有其他设备继续使用该中断号，则释放该中断资源。


Stop all DMA activity
---------------------

在尝试释放 DMA 控制数据之前，务必先停止所有 DMA 操作。
如果不这么做，可能会导致：
	•	内存损坏，
	•	系统卡死，
	•	甚至在某些芯片组上发生严重崩溃（hard crash）。

在禁用 IRQ 之后再停止 DMA，可以避免竞态条件（race condition），
因为 IRQ 处理程序可能会重新启动 DMA 引擎。

尽管这一步听起来简单又显而易见，过去一些“成熟”的驱动程序也曾因此出错。


Release DMA buffers
-------------------

一旦 DMA 停止，首先清理 streaming 类型的 DMA：
	•	即：取消映射（unmap）数据缓冲区；
	•	并在有“上游”所有者的情况下，将缓冲区返回给上游所有者。

然后，再清理用于控制数据的 “consistent”一致性缓冲区。

详细的取消映射接口说明请参考文档：
Documentation/core-api/dma-api.rst。


Unregister from other subsystems
--------------------------------

大多数底层 PCI 设备驱动程序还会支持其他子系统，例如：
	•	USB、
	•	ALSA、
	•	SCSI、
	•	NetDev、
	•	Infiniband 等。

请确保你的驱动在卸载时没有遗漏这些子系统分配的资源。
否则，常见的后果是：当子系统试图调用已卸载的驱动时，
系统就会发生 Oops（内核崩溃）或 panic（严重错误）。

Disable Device from responding to MMIO/IO Port addresses
--------------------------------------------------------

调用 io_unmap() 来取消映射 MMIO 或 IO 端口资源，
然后再调用 pci_disable_device()。

这一步与 pci_enable_device() 是对称的相反操作。
注意：在调用 pci_disable_device() 之后，不要再访问设备寄存器。


Release MMIO/IO Port Resource(s)
--------------------------------

调用 pci_release_region() 用于将 MMIO 或 IO 端口范围标记为可用。
如果不这么做，通常会导致无法重新加载该驱动程序。


How to access PCI config space
==============================

你可以使用 pci_(read|write)_config_(byte|word|dword) 来访问由 struct pci_dev * 表示的设备的配置空间。
这些函数在成功时返回 0，失败时返回错误码（例如 PCIBIOS_...），该错误码可以通过 pcibios_strerror 转换为文本字符串。
大多数驱动程序默认对有效的 PCI 设备的访问不会失败。

如果你没有可用的 struct pci_dev，可以使用 pci_bus_(read|write)_config_(byte|word|dword) 来访问指定总线上的某个设备和功能号。

如果你需要访问配置头中标准部分的字段，请使用在 <linux/pci.h> 中声明的符号名称和位定义。

如果你需要访问 PCI 扩展能力（Extended PCI Capability）寄存器，只需调用 pci_find_capability() 并指定所需的能力类型，它将帮你定位对应的寄存器块。


Other interesting functions
===========================

=============================	================================================
pci_get_domain_bus_and_slot()	根据指定的 domain（域号）、bus（总线号）和 slot/function（插槽号/功能号）查找对应的 pci_dev 结构体。如果找到该设备，会自动增加其引用计数。
pci_set_power_state()		      设置 PCI 电源管理状态（0 = D0 全功率，…，3 = D3 关闭电源状态）。
pci_find_capability()		      在设备的能力列表中查找指定的 PCI 能力（Capability），并返回其配置空间中的偏移地址。
pci_resource_start()		      返回指定 PCI 区域（BAR）在总线地址空间中的起始地址
pci_resource_end()		        返回指定 PCI 区域（BAR）在总线地址空间中的结束地址
pci_resource_len()		        返回指定 PCI 区域（BAR）的字节长度。
pci_set_drvdata()	 	          为 pci_dev 设置私有驱动数据指针（常用于驱动内部存储设备上下文信息）
pci_get_drvdata()		          获取之前通过 pci_set_drvdata() 设置的私有驱动数据指针
pci_set_mwi()			            启用 Memory-Write-Invalidate（内存写入失效）事务，用于优化写入性能
pci_clear_mwi()			          禁用 Memory-Write-Invalidate（MWI）事务。
=============================	================================================


Miscellaneous hints
===================

在向用户显示 PCI 设备名称时（例如驱动想告诉用户它发现了哪块卡），请使用 pci_name(pci_dev)。

始终通过指向 pci_dev 结构体的指针来引用 PCI 设备。所有 PCI 层的函数都使用这种方式进行识别，这是唯一合理的方式。
除非出于非常特殊的目的，否则不要使用总线/插槽/功能号进行设备标识 —— 在具有多个主总线的系统中，它们的语义可能会非常复杂。

不要在驱动中尝试开启 Fast Back to Back 写操作。总线上所有设备都必须支持这种操作，因此这应由平台代码和通用代码处理，而不是由单独的驱动程序来处理。


Vendor and device identifications
=================================

不要向 include/linux/pci_ids.h 添加新的设备 ID 或厂商 ID，除非这些 ID 会被多个驱动程序共享使用。
如果对你的驱动有帮助，你可以在驱动内部添加私有定义，或者直接使用十六进制常量也可以。

设备 ID 是厂商控制的任意十六进制数字，通常只在一个地方使用，即 pci_device_id 表中。

请务必将新的厂商/设备 ID 提交到：https://pci-ids.ucw.cz/
该站点有一个镜像版本的 pci.ids 文件，托管在 GitHub 上：
https://github.com/pciutils/pciids


Obsolete functions
==================

当你尝试将旧的驱动程序移植到新的 PCI 接口时，可能会遇到以下几个函数。
这些函数已不再出现在内核中，因为它们与热插拔、PCI 域（PCI domains）或合理的锁机制不兼容。

=================	===========================================
pci_find_device()	Superseded by pci_get_device()
pci_find_subsys()	Superseded by pci_get_subsys()
pci_find_slot()		Superseded by pci_get_domain_bus_and_slot()
pci_get_slot()		Superseded by pci_get_domain_bus_and_slot()
=================	===========================================

作为替代方案，仍然可以使用传统的 PCI 设备驱动程序遍历 PCI 设备列表的方法。
不过，这种做法已不被推荐。


MMIO Space and "Write Posting"
==============================

将驱动程序从使用 I/O 端口空间（I/O Port space）转换为使用内存映射 I/O 空间（MMIO space）时，通常需要进行一些额外的修改。
特别是，需要处理“写入回写”（Write Posting）的问题。许多驱动程序（如 tg3、acenic、sym53c8xx_2）已经处理了这个问题。

I/O 端口空间保证写入事务会在 CPU 继续执行之前传送到 PCI 设备。
而对 MMIO 空间的写入则允许 CPU 在写入事务真正到达 PCI 设备之前就继续执行。
这种行为被硬件工程师称为“写入回写”，因为写操作的完成是“提前告知”给 CPU 的，即使实际的数据尚未送达目的地。

因此，对于对时序敏感的代码，应该在 CPU 预期等待操作完成后再执行其他操作的地方添加 readl() 之类的读取操作以刷新写入。
以下是一个经典的“位操作（bit banging）”序列，在 I/O 端口空间中可以这样写：

       for (i = 8; --i; val >>= 1) {
               outb(val & 1, ioport_reg);      /* write bit */
               udelay(10);
       }

如果使用 MMIO 空间，应该改为如下方式：

       for (i = 8; --i; val >>= 1) {
               writeb(val & 1, mmio_reg);      /* write bit */
               readb(safe_mmio_reg);           /* flush posted write */
               udelay(10);
       }

重要的是，“safe_mmio_reg” 不能具有任何副作用，否则可能会干扰设备的正常运行。

另一种需要特别注意的情况是重置 PCI 设备时。
此时应使用 PCI 配置空间（PCI Configuration space）读取操作来刷新 writel() 的写入。
这种做法可以在所有平台上优雅地处理 PCI 主控终止（master abort）问题，尤其当该 PCI 设备在读取时可能没有响应 readl() 时更为重要。

在大多数 x86 平台上，MMIO 读取可能会以“软失败”（Soft Fail）的方式处理主控终止并返回垃圾数据（例如 ~0）；
但在许多 RISC 平台上，这种情况会引发崩溃，也就是“硬失败”（Hard Fail）。
