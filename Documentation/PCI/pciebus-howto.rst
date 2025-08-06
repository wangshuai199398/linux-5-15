.. SPDX-License-Identifier: GPL-2.0
.. include:: <isonum.txt>

===========================================
The PCI Express Port Bus Driver Guide HOWTO
===========================================

:Author: Tom L Nguyen tom.l.nguyen@intel.com 11/03/2004
:Copyright: |copy| 2004 Intel Corporation

About this guide
================

本指南介绍了 PCI Express Port 总线驱动的基础知识,并提供了如何使服务驱动(service drivers)与 PCI Express Port 总线驱动进行注册/注销的相关信息


什么是 PCI Express Port 总线驱动程序
=======================================

一个 PCI Express 端口(Port)是一个逻辑上的 PCI-to-PCI 桥接结构。
PCI Express 端口有两种类型: Root Port(根端口) 和 Switch Port(交换端口)。
	•	Root Port 是从 PCI Express 根复合体(Root Complex)发起 PCI Express 链路的端口。
	•	Switch Port 用于将 PCI Express 链路连接到内部逻辑 PCI 总线。
其中, Switch Port 中的 Secondary Bus 表示交换芯片的内部路由逻辑，这个端口被称为 交换芯片的上行端口(Upstream Port)。
而下行端口(Downstream Port) 是从交换芯片的内部路由总线桥接到下游 PCI Express 链路所连接的总线

一个 PCI Express 端口(Port)根据其类型, 最多可以提供四种不同的功能, 本文档中将这些功能称为服务(services)。

PCI Express 端口的服务包括：
	•	原生热插拔支持(HP)
	•	电源管理事件支持(PME)
	•	高级错误报告支持(AER)
	•	虚拟通道支持(VC)

这些服务可以由一个复杂的统一驱动程序进行处理，也可以由各自对应的服务驱动程序分别独立处理。

为什么要使用 PCI Express Port 总线驱动程序？
========================================

在现有的 Linux 内核中, Linux 设备驱动模型(Device Driver Model) 规定一个物理设备只能由一个驱动程序处理
而 PCI Express 端口是一个具有多个不同服务的 PCI-to-PCI 桥接设备。
为了保持解决方案的清晰和简洁，每个服务可以由其各自的服务驱动程序进行处理。

在这种情况下，多个服务驱动程序会竞争同一个 PCI-to-PCI 桥接设备。

例如，如果 PCI Express 根端口(Root Port)的原生热插拔服务驱动程序被最先加载,
它将占用这个 Root Port, 因此内核就不会再为该 Root Port 加载其它服务驱动程序。

换句话说，在当前驱动模型下，不可能让多个服务驱动同时加载并运行在同一个 PCI-to-PCI 桥设备上。

为了实现多个服务驱动的同时运行，必须引入一个 PCI Express Port 总线驱动(Port Bus Driver)
它用于管理所有已连接的 PCI Express 端口，并根据需要将不同的服务请求分发给相应的服务驱动程序。

使用 PCI Express Port 总线驱动的一些主要优势如下所示：

  - 允许多个服务驱动程序同时运行在一个 PCI-to-PCI 桥接端口设备上

  - 允许服务驱动程序以独立、分阶段的方式实现

  - 允许一个服务驱动程序同时运行在多个 PCI-to-PCI 桥接端口设备上

  - 负责管理和分发 PCI-to-PCI 桥接端口设备的资源，以供请求的服务驱动程序使用

配置 PCI Express Port 总线驱动与服务驱动程序的区别
===============================================================

将 PCI Express Port 总线驱动支持集成进内核
-----------------------------------------------------------------

是否包含 PCI Express Port 总线驱动取决于内核配置中是否启用了 PCI Express 支持
当内核中启用了 PCI Express 支持时，内核将自动将 PCI Express Port 总线驱动作为内核驱动程序包含进来

启用服务驱动程序支持
-------------------------------

PCI 设备驱动程序是基于 Linux 设备驱动模型实现的，所有服务驱动程序本质上都是 PCI 设备驱动程序。

如前所述，一旦内核加载了 PCI Express Port 总线驱动，就无法再加载任何服务驱动程序。

为了适配 PCI Express Port 总线驱动模型，对现有服务驱动程序需要进行一些最小化的修改，
这些修改不会影响其原有功能。

一个服务驱动程序必须使用下方的两个 API 来将其服务注册到 PCI Express Port 总线驱动中（参见第 5.2.1 和 5.2.2 节）。

在调用这些 API 之前，服务驱动程序必须初始化 pcie_port_service_driver 数据结构，
该结构定义在头文件 /include/linux/pcieport_if.h 中。

如果未正确初始化该结构, 将导致身份不匹配(identity mismatch), 从而阻止 PCI Express Port 总线驱动加载该服务驱动程序

pcie_port_service_register
~~~~~~~~~~~~~~~~~~~~~~~~~~
::

  int pcie_port_service_register(struct pcie_port_service_driver *new)

该 API 用于替代 Linux 驱动模型中的 pci_register_driver API
服务驱动程序在模块初始化时应始终调用 pcie_port_service_register。

需要注意的是，在服务驱动被加载后，像 pci_enable_device(dev) 和 pci_set_master(dev) 这样的调用就不再需要，因为这些调用已经由 PCI Port 总线驱动执行

pcie_port_service_unregister
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

  void pcie_port_service_unregister(struct pcie_port_service_driver *new)

pcie_port_service_unregister 用于替代 Linux 驱动模型中的 pci_unregister_driver

当模块退出时，服务驱动程序应始终调用该函数

Sample Code
~~~~~~~~~~~

以下是初始化端口服务驱动程序数据结构的示例服务驱动代码
::

  static struct pcie_port_service_id service_id[] = { {
    .vendor = PCI_ANY_ID,
    .device = PCI_ANY_ID,
    .port_type = PCIE_RC_PORT,
    .service_type = PCIE_PORT_SERVICE_AER,
    }, { /* end: all zeroes */ }
  };

  static struct pcie_port_service_driver root_aerdrv = {
    .name		= (char *)device_name,
    .id_table	= &service_id[0],

    .probe		= aerdrv_load,
    .remove		= aerdrv_unload,

    .suspend	= aerdrv_suspend,
    .resume		= aerdrv_resume,
  };

以下是用于注册和注销服务驱动程序的示例代码
::

  static int __init aerdrv_service_init(void)
  {
    int retval = 0;

    retval = pcie_port_service_register(&root_aerdrv);
    if (!retval) {
      /*
      * FIX ME
      */
    }
    return retval;
  }

  static void __exit aerdrv_service_exit(void)
  {
    pcie_port_service_unregister(&root_aerdrv);
  }

  module_init(aerdrv_service_init);
  module_exit(aerdrv_service_exit);

可能的资源冲突
===========================

由于同一个 PCI-to-PCI 桥接端口设备上的所有服务驱动程序都允许同时运行，下面列出了一些可能发生的资源冲突以及对应的解决方案

MSI and MSI-X Vector Resource
-----------------------------

一旦在某个设备上启用了 MSI 或 MSI-X 中断，该设备将保持在该模式，直到它们被再次禁用。
由于同一 PCI-to-PCI 桥接端口的多个服务驱动程序共享同一个物理设备，如果某个单独的服务驱动启用或禁用了 MSI/MSI-X 模式，可能会导致不可预期的行为。

为避免上述情况，所有服务驱动程序都不允许切换设备的中断模式。

由 PCI Express Port 总线驱动负责确定中断模式，这一过程对服务驱动来说应当是透明的。

服务驱动只需要知道分配给 struct pcie_device 中 irq 字段的中断向量号，
该结构在 PCI Express Port 总线驱动对每个服务驱动进行 probe 时传入。

服务驱动应通过 (struct pcie_device*)dev->irq 来调用 request_irq 和 free_irq。

此外，中断模式也会被存储在 struct pcie_device 的 interrupt_mode 字段中。

PCI 内存 / I/O 映射区域
----------------------------

用于 PCI Express 电源管理(PME)、高级错误报告(AER)、热插拔(HP)和虚拟通道(VC)的服务驱动程序，都会访问 PCI Express 端口上的 PCI 配置空间。
在所有情况下，所访问的寄存器彼此是独立的。
该补丁的假设是：所有服务驱动程序都会遵循规范行为，不会覆盖其他服务驱动的配置设置。

PCI 配置寄存器
--------------------

每个服务驱动程序在其各自的能力结构(capability structure)上执行 PCI 配置操作，
除了 PCI Express 能力结构，其中的 Root Control 寄存器 和 Device Control 寄存器会被 PME 和 AER 两个服务驱动共享。
该补丁假设所有服务驱动程序都会遵守规范行为，不会覆盖其他服务驱动的配置设置。
