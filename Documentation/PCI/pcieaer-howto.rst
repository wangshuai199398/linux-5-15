.. SPDX-License-Identifier: GPL-2.0
.. include:: <isonum.txt>

===========================================================
The PCI Express Advanced Error Reporting Driver Guide HOWTO
===========================================================

:Authors: - T. Long Nguyen <tom.l.nguyen@intel.com>
          - Yanmin Zhang <yanmin.zhang@intel.com>

:Copyright: |copy| 2006 Intel Corporation

Overview
===========

About this guide
----------------

本指南介绍了 PCI Express 高级错误报告(AER)驱动程序的基础知识, 
并提供了如何使用该驱动程序的信息，以及如何使终端设备的驱动程序与 PCI Express AER 驱动兼容的方法。


什么是 PCI Express AER(级错误报告)驱动程序？
-----------------------------------

PCI Express 的错误信号可能发生在 PCI Express 链路本身，也可能代表通过该链路发起的事务而产生。
PCI Express 定义了两种错误报告机制: 基本能力(baseline capability) 和 高级错误报告能力(Advanced Error Reporting capability,简称 AER)
	•	基本能力 是所有 PCI Express 组件都必须具备的，提供一组最小定义的错误报告要求；
	•	高级错误报告能力 是通过 PCI Express 的扩展能力结构实现的，提供更强大、更加完善的错误报告机制。

PCI Express AER 驱动程序提供了一个基础架构，以支持 PCI Express 的高级错误报告能力。
该驱动程序提供了以下三个基本功能：（接下来的内容通常会列出这三项功能）

  - 收集发生错误时的完整错误信息
  - 向用户报告错误
  - 执行错误恢复操作

AER 驱动程序仅绑定那些支持 PCI Express AER 能力的根端口(Root Port)


用户指南
==========

将 PCI Express AER Root 驱动程序集成到 Linux 内核中
-------------------------------------------------------------

PCI Express AER Root 驱动程序是一个附加在 PCI Express Port 总线驱动程序上的 Root Port 服务驱动程序。

如果用户希望使用该驱动程序，必须将其编译进内核。

配置项 CONFIG_PCIEAER 用于启用该功能。它依赖于 CONFIG_PCIEPORTBUS, 因此请设置: CONFIG_PCIEPORTBUS = y 和 CONFIG_PCIEAER = y

加载 PCI Express AER Root 驱动程序
--------------------------------

某些系统的固件中已实现 AER 支持。当固件和 Linux 同时处理 AER 事件时，可能会导致不可预期的行为。
因此，除非固件通过 ACPI 的 _OSC 方法将 AER 控制权授予操作系统, Linux 不会处理 AER 事件。
关于 _OSC 的使用详情，请参阅 PCI FW 3.0 规范。

AER 错误输出
----------------

当捕获到 PCIe AER 错误时，系统会将错误信息输出到控制台。
如果是可纠正错误(correctable error), 则作为警告(warning)输出, 否则将作为错误(error)输出。
因此，用户可以根据不同的日志级别来过滤可纠正的错误消息

下面是一个示例::

  0000:50:00.0: PCIe Bus Error: severity=Uncorrected (Fatal), type=Transaction Layer, id=0500(Requester ID)
  0000:50:00.0:   device [8086:0329] error status/mask=00100000/00000000
  0000:50:00.0:    [20] Unsupported Request    (First)
  0000:50:00.0:   TLP Header: 04000001 00200a03 05010000 00050100

在该示例中, Requester ID 表示将错误消息发送到 Root Port 的设备的 ID
关于其他字段的含义，请参考 PCI Express 规范

AER 统计信息 / 计数器
-------------------------

当捕获到 PCIe AER 错误时，相关的计数器和统计信息也会通过 sysfs 属性 的形式对外公开，其详细说明文档位于：
Documentation/ABI/testing/sysfs-bus-pci-devices-aer_stats

开发者指南
===============

要启用对 AER 的支持，驱动程序需要配置其设备内的 AER 能力结构，并提供相关的回调函数。

为了更好地支持 AER, 开发者首先需要理解 AER 的工作机制。

PCI Express 错误分为两类: 可纠正错误(correctable errors) 和 不可纠正错误(uncorrectable errors)。
这种分类是基于错误的影响程度，有些错误可能仅导致性能下降，而有些则会导致功能失败。

	•	可纠正错误 不会影响接口功能。PCI Express 协议可以在 无需软件介入且无数据丢失 的情况下自行恢复。这些错误由硬件检测并自动纠正。
	•	与之不同，不可纠正错误 会影响接口的功能。它们可能导致某个事务或某条 PCI Express 链路变得不可靠。根据具体情况，不可纠正错误又分为：
	  •	非致命错误(non-fatal errors): 仅导致某个事务不可靠，但链路本身仍然正常；
	  •	致命错误(fatal errors): 会导致整条链路不可靠。

当启用了 AER 后，如果某个 PCIe 设备捕获到错误，它会自动将一条错误消息发送给其上方的 PCIe 根端口(Root Port)。
Root Port 接收到错误报告消息后，会在其 PCI Express 能力结构 中进行内部处理并记录错误信息。
记录的内容包括：
	•	将报告错误的设备的 Requester ID 存入 Error Source Identification Registers
	•	将错误状态位写入 Root Error Status Register
	•	如果在 Root Error Command Register 中启用了 AER 错误报告功能，
一旦检测到错误, Root Port 会触发中断。
请注意，以上描述的错误都是与 PCI Express 层级结构和链路相关的错误。
它们不包括设备自身特定的错误，因为这些设备级错误仍然会直接发送给对应的设备驱动程序。

请注意，以上所描述的错误是与 PCI Express 层级结构和链路 相关的错误。
这些错误不包括设备自身的特定错误，因为设备特定的错误仍然会直接发送给相应的设备驱动程序。

配置 AER 能力结构
--------------------------------------

支持 AER 的 PCI Express 组件驱动程序需要修改设备控制寄存器(device control registers)以启用 AER。
它们还可以修改 AER 寄存器，包括 掩码寄存器(mask registers) 和 严重性寄存器(severity registers)。
可以使用辅助函数 pci_enable_pcie_error_reporting 来启用 AER,
详见第 3.3 节。

提供回调函数
-----------------

回调函数 reset_link 用于重置 PCI Express 链路
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

当发生致命错误(fatal error)时, 此回调函数用于重置 PCI Express 物理链路。

Root Port 的 AER 服务驱动程序提供了一个默认的 reset_link 函数，
但由于不同的上行端口(upstream ports)可能有不同的链路重置规范, 因此所有上行端口都应提供它们自己的 reset_link 实现。

第 3.2.2.2 节中提供了关于何时调用 reset_link 的详细信息。

PCI 错误恢复回调函数
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PCI Express AER Root 驱动程序在执行错误恢复操作时，
使用错误回调函数(error callbacks)与相关层级中的下游设备驱动进行协调。

struct pci_driver 中有一个指针 err_handler, 它指向一个 pci_error_handlers 结构，该结构包含多个回调函数指针。
AER 驱动遵循 pci-error-recovery.txt 中定义的规则，除了 PCI Express 特有的部分(例如 reset_link)

有关这些回调函数的详细定义，请参考 pci-error-recovery.txt。

下面的章节将说明在何时调用这些错误回调函数。


可纠正错误
~~~~~~~~~~~~~~~~~~

可纠正错误对接口功能没有任何影响。
PCI Express 协议可以在无需软件介入且不会丢失数据的情况下自动恢复。

这些错误不需要执行任何恢复操作。

AER 驱动会相应地清除设备的可纠正错误状态寄存器，并记录这些错误日志。


不可纠正错误（非致命和致命）
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

如果错误消息表明是非致命错误(non-fatal error), 则不需要在上游执行链路重置(link reset)。

AER 驱动会调用 error_detected(dev, pci_channel_io_normal),对该错误层级内所有相关驱动程序进行通知。

例如：
  EndPoint <==> DownstreamPort B <==> UpstreamPort A <==> RootPort
如果 Upstream Port A 捕获到一个 AER 错误，那么相关的层级包括 Downstream Port B 和 EndPoint。

驱动程序可以根据自身能否恢复，返回以下结果之一：
	•	PCI_ERS_RESULT_CAN_RECOVER
	•	PCI_ERS_RESULT_DISCONNECT
	•	PCI_ERS_RESULT_NEED_RESET

随后, AER 驱动会决定是否进入下一步，如调用 mmio_enabled。

如果错误消息表明是致命错误(fatal error), 内核将向该层级中所有驱动广播：
  error_detected(dev, pci_channel_io_frozen)
然后, 必须在上游执行链路重置(link reset)

由于不同类型的设备可能使用不同的链路重置方式，
**AER 端口服务驱动(port service driver)**需要通过 pcie_do_recovery() 函数的回调参数，
提供实现链路重置的函数。

如果 reset_link 不为 NULL, 恢复函数将使用它来执行链路重置。

如果：
	•	error_detected() 返回 PCI_ERS_RESULT_CAN_RECOVER, 且
	•	reset_link() 返回 PCI_ERS_RESULT_RECOVERED,

那么错误处理流程将继续进入 mmio_enabled 阶段


辅助函数
----------------
::

  int pci_enable_pcie_error_reporting(struct pci_dev *dev);

pci_enable_pcie_error_reporting 用于在设备检测到错误时，启用向 Root Port 发送错误消息的功能。
注意：设备默认不会启用错误报告功能，因此设备驱动程序需要显式调用此函数来启用它。

::

  int pci_disable_pcie_error_reporting(struct pci_dev *dev);

pci_disable_pcie_error_reporting 用于在设备检测到错误时，禁用向 Root Port 发送错误消息的功能。

::

  int pci_aer_clear_nonfatal_status(struct pci_dev *dev);`

pci_aer_clear_nonfatal_status 用于清除不可纠正错误状态寄存器中的非致命错误标志位。

常见问题解答 或 常见问答(FAQ)
------------------------

Q:
  如果一个 PCI Express 设备驱动程序没有提供错误恢复处理函数(即 pci_driver->err_handler == NULL)会发生什么?

A:
  与该驱动程序绑定的设备将无法进行错误恢复。如果该错误是致命的，内核将打印警告信息。详情请参考第 3 节。

Q:
  如果一个上游端口的服务驱动程序没有提供 reset_link 回调函数会怎样？

A:
  如果错误是由与该服务驱动绑定的上游端口报告的，致命错误恢复将失败。

Q:
  该基础架构如何处理不支持 PCI Express 的驱动程序？

A:
  该基础架构在错误发生时仍会调用驱动程序的错误回调函数。但如果驱动程序不支持 PCI Express, 则该设备可能不会将自身的错误报告发送到 Root Port。

Q:
  为了使驱动程序兼容 PCI Express AER Root 驱动，需要进行哪些修改？

A:
  驱动程序可以调用辅助函数来启用设备中的 AER 功能，并清除不可纠正错误状态寄存器。
  请参考第 3.3 节。


软件错误注入
========================

调试 PCIe AER 错误恢复代码比较困难，因为很难触发真实的硬件错误。
此时可以使用**基于软件的错误注入(software-based error injection)来模拟各种类型的 PCIe 错误。

首先，你需要在内核配置中启用 PCIe AER 软件错误注入功能，即 .config 文件中应包含以下配置项之一：
  
  CONFIG_PCIEAER_INJECT=y

或

  CONFIG_PCIEAER_INJECT=m

使用新内核重启系统，或插入相应模块后，系统将创建一个名为 /dev/aer_inject 的设备文件。
然后，你需要一个名为 aer-inject 的用户空间工具，可以从以下地址获取该工具源码：

  https://git.kernel.org/cgit/linux/kernel/git/gong.chen/aer-inject.git/

关于 aer-inject 的更多信息，请参考其源代码附带的文档说明
