.. SPDX-License-Identifier: GPL-2.0

==================
PCI Error Recovery
==================


:Authors: - Linas Vepstas <linasvepstas@gmail.com>
          - Richard Lary <rlary@us.ibm.com>
          - Mike Mason <mmlnx@us.ibm.com>


许多 PCI 总线控制器能够检测总线上各种硬件错误，例如数据线和地址线上的奇偶校验错误，以及 SERR 和 PERR 错误。
一些更先进的芯片组（如 PCI-E 芯片组以及 IBM Power4、Power5 和 Power6 架构的 pSeries 服务器上的 PCI 主桥）能够处理这些错误。

常见的处理方式是断开受影响的设备，停止对其所有 I/O 操作。
这样做的目的是避免系统损坏，例如防止因 DMA 访问“异常地址”而导致的系统内存损坏。
通常还会提供重连机制，以便对受影响的 PCI 设备进行重置并使其恢复正常工作状态。
重置过程需要受影响的设备驱动程序与 PCI 控制器芯片之间进行协调。

本文档描述了一个通用的 API，用于在总线断开时通知设备驱动程序，并执行错误恢复操作。
该 API 从 Linux 内核版本 2.6.16 开始被实现。

错误报告与恢复分为多个步骤进行。

首先，当某个 PCI 硬件错误导致总线断开时，该事件会尽快报告给所有受影响的设备驱动程序，包括多功能卡上的多个驱动实例。

这样做的目的是防止驱动程序陷入死循环（例如在等待某个永远不会变化的 I/O 寄存器时发生死锁），并为驱动程序提供机会，根据需要延迟处理新的 I/O 请求。

接下来，恢复过程分多个阶段进行。其中大部分复杂性来自于需要处理多功能设备，也就是那些关联了多个设备驱动程序的设备。
在第一个阶段，每个驱动程序都可以表明其希望执行哪种类型的复位操作，选项包括：简单地重新启用 I/O，或请求进行插槽复位（slot reset）。

如果任何驱动程序请求进行插槽复位（slot reset），那么就会执行该复位操作。

在完成复位和/或重新启用 I/O 之后，所有驱动程序会再次被通知，以便它们执行任何所需的设备设置或配置。
所有这些操作完成后，系统会发出最终的“恢复正常操作”事件。

之所以选择内核级的实现而不是用户空间的实现，最主要的原因是需要处理与存储介质相连的 PCI 设备发生总线断开的情况，特别是包含根文件系统的设备发生断开时。
如果根文件系统被断开，用户空间的机制将不得不经历大量复杂操作才能完成恢复。而目前的大多数 Linux 文件系统并不容忍底层块设备的断开与重新连接。

相比之下，在设备驱动中处理总线错误要容易得多。
事实上，大多数设备驱动程序已经具备类似的恢复流程；例如，SCSI 通用层就已经提供了处理 SCSI 总线错误和总线复位的多种机制。


Detailed Design
===============

以下是设计和实现细节，基于 2005 年 4 月 5 日前后与 Ben Herrenschmidt 的一系列公开邮件讨论。

错误恢复 API 通过一个函数指针结构体的形式向驱动程序提供支持，该结构体被赋值给 struct pci_driver 中的一个新字段。
未提供该结构体的驱动程序被视为“不具备错误感知能力”，此时实际采取的恢复步骤将依赖于平台实现。
例如，在 PowerPC 架构中，会模拟一次 PCI 热插拔的移除/添加过程。

该结构体的形式如下：

	struct pci_error_handlers
	{
		int (*error_detected)(struct pci_dev *dev, pci_channel_state_t);
		int (*mmio_enabled)(struct pci_dev *dev);
		int (*slot_reset)(struct pci_dev *dev);
		void (*resume)(struct pci_dev *dev);
	};

可能的通道状态如下：

	typedef enum {
		pci_channel_io_normal,  /* I/O channel is in normal state */
		pci_channel_io_frozen,  /* I/O to channel is blocked */
		pci_channel_io_perm_failure, /* PCI card is dead */
	} pci_channel_state_t;

可能的返回值：

	enum pci_ers_result {
		PCI_ERS_RESULT_NONE,        /* no result/none/not supported in device driver */
		PCI_ERS_RESULT_CAN_RECOVER, /* Device driver can recover without slot reset */
		PCI_ERS_RESULT_NEED_RESET,  /* Device driver wants slot to be reset. */
		PCI_ERS_RESULT_DISCONNECT,  /* Device has completely failed, is unrecoverable */
		PCI_ERS_RESULT_RECOVERED,   /* Device driver is fully recovered and operational */
	};

驱动程序不必实现所有这些回调函数；
但是，如果实现了其中任何一个，则必须实现 error_detected()。
如果某个回调函数未实现，则视为该功能在该驱动中不受支持。

例如，如果未实现 mmio_enabled() 和 resume()，则默认认为驱动程序不执行任何直接恢复操作，而是需要执行插槽复位（slot reset）。
通常，驱动程序会希望了解 slot_reset() 的相关信息。

平台在从 PCI 错误事件中恢复的过程中所采取的实际步骤是依赖于具体平台的，但会遵循以下描述的通用流程顺序。


第 0 步：错误事件
-------------------
PCI 硬件检测到一个 PCI 总线错误。
在 PowerPC 架构中，插槽会被隔离，所有的 I/O 操作都会被阻断：所有读取操作返回 0xffffffff，所有写入操作则被忽略。


第 1 步：通知
--------------------
平台会对所有受该错误影响的驱动实例调用 error_detected() 回调函数。

此时，设备可能已经无法访问，这取决于具体平台（例如在 PowerPC 上插槽会被隔离）。
驱动程序可能已经因为某个 I/O 失败而“察觉”到错误，但这个回调是正式的“同步点”，它给驱动提供了一个机会来执行清理操作，例如等待挂起的任务（定时器之类）完成；
此函数中可以使用信号量、调度等操作，但不能访问设备。
在该函数中以及返回后，驱动程序不应执行任何新的 I/O 操作。
该函数在任务上下文中调用，可以视为一种“安静（quiesce）”状态。关于中断，请参考本文最后的说明。

所有参与该系统的驱动程序都必须实现此回调函数。驱动程序必须返回以下结果代码之一：

  - PCI_ERS_RESULT_CAN_RECOVER
      如果驱动程序认为只需通过执行 I/O 操作就可以恢复硬件，或者希望获得机会提取某些诊断信息（见下文的 mmio_enable），则返回该值。

  - PCI_ERS_RESULT_NEED_RESET
      如果驱动程序认为必须执行插槽重置（slot reset）才能恢复，则返回该值

  - PCI_ERS_RESULT_DISCONNECT
      如果驱动程序完全放弃恢复，不打算再使用该设备，则返回该值

接下来的恢复步骤取决于驱动程序返回的结果代码：

如果同一段/插槽上的所有驱动程序都返回 PCI_ERS_RESULT_CAN_RECOVER，则平台应重新启用该插槽的 I/O（如果平台不支持插槽隔离，则可什么都不做），并进入第 2 步（MMIO 启用）。

如果任意驱动程序返回了 PCI_ERS_RESULT_NEED_RESET，则进入第 4 步（插槽重置）。

如果平台无法恢复该插槽，则进入第 6 步（永久故障）。

.. note::

   当前的 PowerPC 实现假设设备驱动程序不会在此例程中进行调度或使用信号量；
   因为当前的 PowerPC 实现使用一个内核线程来通知所有设备；
   因此，如果某个设备在此过程中进入休眠或发生调度，所有设备的通知过程都会受到影响。
   
   如果要改进这一点，就需要在错误恢复实现中引入复杂的多线程逻辑（例如等待所有通知线程“汇合”之后再继续恢复流程）。
   但这看起来过于复杂，不值得实现。

   当前的 PowerPC 实现并不特别在意设备此时是否尝试进行 I/O 操作。
   所有的 I/O 操作都会失败，读取操作会返回 0xff，写入操作则会被直接丢弃。
   如果对被冻结的适配器发起的 I/O 次数超过 EEH_MAX_FAILS，EEH（Extended Error Handling）机制会假定该设备驱动进入了死循环，并在 syslog 中打印错误日志。
   此时，必须重启系统才能让该设备重新工作。


STEP 2: MMIO Enabled
--------------------
平台会重新启用设备的 MMIO（内存映射 I/O），但通常不会启用 DMA（直接内存访问），然后调用所有受影响设备驱动的 mmio_enabled() 回调函数。

这是“早期恢复”阶段的回调。
此时允许执行 I/O 操作，但对 DMA 有一定限制。

这个回调并不是让驱动程序重新开始正常操作，而是用于读取或写入设备以提取诊断信息（如果有的话），或者执行一些类似本地设备复位的操作，但不应该重启正常的工作流程。

只有当某段总线上的所有驱动都同意尝试恢复，并且硬件没有执行自动链路重置时，才会调用此回调。
如果平台不能在不进行插槽复位或链路复位的前提下重新启用 I/O，则不会调用该回调函数，而是会直接进入第 3 步（链路重置）或第 4 步（插槽重置）。

.. note::

   以下是一个提案；目前还没有任何平台实现这一机制：

   提案：所有的 I/O 操作应该在此回调中同步完成。若在此过程中发生错误，将通过常规的 pci_check_whatever() API 返回错误码，不会因此触发新的 error_detected() 回调。然而，如果发生的错误导致整个 segment（段）的 I/O 被重新阻断，那么此前该段其他设备所进行的恢复将被视为无效，整个 segment 将被强制进入下一状态，例如链路重置或插槽重置。

   驱动程序应返回以下结果码之一：

  - PCI_ERS_RESULT_RECOVERED
      如果驱动认为设备已完全恢复且可以开始正常运行，则返回此值。
      注意：返回此值并不意味着驱动一定会被允许继续运行，因为同一段上的其他驱动可能失败并触发了插槽重置。

  - PCI_ERS_RESULT_NEED_RESET
      如果驱动认为当前设备状态无法恢复，需要进行插槽复位才能继续，则返回此值。

  - PCI_ERS_RESULT_DISCONNECT
      与上述相同，表示彻底失败，即使复位后也无法恢复，驱动已“死亡”（这个含义尚需进一步精确定义）。

接下来平台的处理步骤将取决于驱动返回的结果：

  •	如果所有驱动都返回 PCI_ERS_RESULT_RECOVERED，则平台继续进入第 3 步（链路重置）或第 5 步（恢复操作）。
	•	如果有任一驱动返回 PCI_ERS_RESULT_NEED_RESET，则平台进入第 4 步（插槽复位）。


STEP 3: Link Reset
------------------
平台会重置链路。这是 PCI-Express 特有的步骤，当检测到一个致命错误且该错误可以通过重置链路来“解决”时，就会执行此操作。


STEP 4: Slot Reset
------------------

当返回值为 PCI_ERS_RESULT_NEED_RESET 时，平台将对请求重置的 PCI 设备执行插槽（slot）重置。
平台实际执行插槽重置的步骤是平台相关的。
在插槽重置完成后，平台会调用设备的 slot_reset() 回调函数。

PowerPC 平台实现了两种级别的插槽重置：
	•	软重置（soft reset，默认）
	•	基础重置（fundamental reset，可选）

PowerPC 的软重置是通过拉高适配器的 #RST 引脚来实现的，并随后将 PCI BAR（基地址寄存器）和 PCI 配置头恢复为相当于系统刚通电、由 BIOS 或系统固件初始化后的状态。
软重置也称为热重置（hot-reset）。

PowerPC 的基础重置仅适用于 PCI Express 设备，它会将设备的状态机、硬件逻辑、端口状态和配置寄存器初始化为默认状态。

对于大多数 PCI 设备，软重置已足够实现恢复。
但对于某些软重置不足以恢复的 PCI Express 设备，提供了可选的基础重置支持。

如果平台支持 PCI 热插拔（hotplug），则重置也可能通过控制插槽电源开/关来完成。

平台必须将 PCI 配置空间恢复到“初始上电状态”，而不是“之前的状态”。
因为在插槽重置后，设备驱动通常会执行标准的设备初始化流程，配置空间如果不一致，可能导致设备挂起、内核崩溃或静默数据损坏。

这个 slot_reset() 回调让驱动有机会重新初始化硬件（如重新加载固件等）。
在这个阶段，驱动可以假设设备处于“全新”状态并可正常工作。
插槽此时已解冻，驱动拥有对 PCI 配置空间、MMIO 空间以及 DMA 的完全访问权限。
中断（无论是 Legacy、MSI 还是 MSI-X）也都可用。

此时，驱动不应立即恢复正常的 I/O 操作。
如果所有设备驱动都报告成功，平台会继续调用 resume() 来完成恢复流程，并允许驱动恢复正常的 I/O 操作。

如果驱动在重置后仍无法使设备恢复正常工作，它仍可以在此函数中返回关键错误。
如果平台此前进行了软重置，它可能尝试执行硬重置（例如断电重启），然后再次调用 slot_reset()。
如果设备仍无法恢复，说明已经无能为力，平台通常会报告“永久性故障”，该设备将被视为“死亡”。

对于多功能卡（multi-function card），多个驱动实例之间需要协调，确定由哪一个实例负责执行一次性或全局设备初始化。
例如，Symbios sym53cxx2 驱动只在 PCI function 0 上执行初始化：

	+       if (PCI_FUNC(pdev->devfn) == 0)
	+               sym_reset_scsi_bus(np, 0);

返回结果码：
	- PCI_ERS_RESULT_DISCONNECT
	  表示无法恢复，设备已经彻底故障

对于需要基础重置的 PCI Express 卡，驱动必须在其 probe 函数中设置 pci_dev 结构体中的 needs_freset 标志位。
例如，QLogic 的 qla2xxx 驱动会为某些 PCI 卡类型设置该位：

	+	/* Set EEH reset type to fundamental if required by hba  */
	+	if (IS_QLA24XX(ha) || IS_QLA25XX(ha) || IS_QLA81XX(ha))
	+		pdev->needs_freset = 1;
	+

平台随后会进入：
	•	步骤 5：恢复操作（Resume Operations），或
	•	步骤 6：永久性故障（Permanent Failure）。

.. note::

   当前的 PowerPC 实现中，如果驱动返回 PCI_ERS_RESULT_DISCONNECT，平台不会尝试执行电源循环重置（power-cycle reset）。
   不过，它可能应该这么做。


STEP 5: Resume Operations
-------------------------
如果总线段上的所有驱动程序在前面三个回调函数中的某一个中都返回了 PCI_ERS_RESULT_RECOVERED，
则平台会调用所有受影响设备驱动程序的 resume() 回调函数。

该回调函数的目的是通知驱动程序可以重新启动活动，也就是说一切已经恢复正常。
这个回调函数不会返回结果码。

此时，如果再次发生新的错误，平台将重新启动一个新的错误恢复流程。

STEP 6: Permanent Failure
-------------------------

发生了“永久性故障”，平台无法恢复该设备。平台将以 pci_channel_state_t 值为 pci_channel_io_perm_failure 调用 error_detected()。

此时，设备驱动程序应假设最坏情况发生。它应当：
	•	取消所有未完成的 I/O；
	•	拒绝所有新的 I/O，请求时返回 -EIO 给上层；
	•	清理其所有内存；
	•	并将自身从内核操作中移除，就像系统关机时所做的那样。

平台通常会以某种方式通知系统管理员发生了永久性故障。如果该设备支持热插拔，管理员可能需要移除并更换该设备。

但请注意，并非所有故障都是真正“永久性”的。
有些故障可能是由于设备过热或卡未插牢引起的。许多 PCI 错误事件实际上是由软件缺陷引起的，例如 DMA 到非法地址，或者由于编程错误导致的错误分离事务（split transaction）。

关于这类软件错误在真实环境中的发生原因，可参考文档 powerpc/eeh-pci-error-recovery.txt 中的讨论。


Conclusion; General Remarks
---------------------------
回调函数的调用方式取决于平台的策略。
对于不具备插槽重置能力的平台，可能会选择“忽略”无法恢复的驱动程序（即将其断开），并尝试让同一总线段上的其他设备继续恢复。
需要注意的是，在大多数实际应用中，每个总线段上通常只有一个驱动程序。

关于中断的一点说明：如果你收到一个中断，而此时设备已经失效或被隔离，那就有问题了 :

当前的策略是将此问题交由平台策略处理。也就是说，恢复 API 的要求如下：
	•	在检测到错误之后直到调用 slot_reset 回调之前，不能保证任何设备上的中断能够正常传递。在 slot_reset 被调用之后，才预期中断功能恢复正常。
	•	也不能保证中断一定会被停止。
  也就是说，如果一个驱动在错误发生后仍接收到中断，或者在中断处理程序中检测到错误，导致无法正确确认（ack）中断（也就无法移除中断源），那么驱动应当直接返回 IRQ_NOTHANDLED。
  这类情况应该由平台处理，通常的做法是在错误处理期间屏蔽中断源。

  平台应“知道”哪些中断是与支持错误管理的插槽相关联的，并能够在错误处理过程中临时禁用相应的中断号（这并不太复杂）。
  这样做可能会对其他共享该中断的设备造成一定的中断延迟，但这是不可避免的。高端平台通常不会让多个设备共享同一个中断号。

.. note::

PowerPC 平台的实现细节可参考文件：
   Documentation/powerpc/eeh-pci-error-recovery.rst

截至本文撰写时，已有越来越多的设备驱动程序添加了错误恢复功能的补丁。虽然这些补丁尚未全部合并进主线内核，但它们可以作为“示例”供参考：

   - drivers/scsi/ipr
   - drivers/scsi/sym53c8xx_2
   - drivers/scsi/qla2xxx
   - drivers/scsi/lpfc
   - drivers/next/bnx2.c
   - drivers/next/e100.c
   - drivers/net/e1000
   - drivers/net/e1000e
   - drivers/net/ixgb
   - drivers/net/ixgbe
   - drivers/net/cxgb3
   - drivers/net/s2io.c

The End
-------
