.. SPDX-License-Identifier: GPL-2.0
.. include:: <isonum.txt>

====================================
PCI Express I/O Virtualization Howto
====================================

:Copyright: |copy| 2009 Intel Corporation
:Authors: - Yu Zhao <yu.zhao@intel.com>
          - Donald Dutile <ddutile@redhat.com>

Overview
========

What is SR-IOV
--------------

单根 I/O 虚拟化（SR-IOV，Single Root I/O Virtualization）是一种 PCI Express 扩展功能，它可以将一个物理设备虚拟成多个虚拟设备。
该物理设备称为物理功能（PF，Physical Function），而虚拟出的设备称为虚拟功能（VF，Virtual Function）。

PF 可以通过封装在该扩展能力中的寄存器动态控制 VF 的分配。
默认情况下，此功能是未启用的，PF 表现为一个传统的 PCIe 设备。
一旦启用该功能，每个 VF 的 PCI 配置空间都可以通过其各自的总线号（Bus）、设备号（Device）和功能号（Function Number）（也称为 Routing ID）进行访问。
同时，每个 VF 也拥有自己的 PCI 内存空间，用于映射其寄存器集。

VF 的设备驱动程序会操作这些寄存器，以便让虚拟功能设备具备实际功能并表现为一个真实存在的 PCI 设备。

User Guide
==========

How can I enable SR-IOV capability
----------------------------------

SR-IOV 的启用有多种方式可供选择。

第一种方法中，由设备驱动程序（PF 驱动）通过 SR-IOV 核心提供的 API 来控制该功能的启用和禁用。
如果硬件具备 SR-IOV 功能，在加载其 PF 驱动时，就会启用 SR-IOV 以及该 PF 所关联的所有 VF。
一些 PF 驱动还要求设置一个模块参数来指定启用的 VF 数量。

第二种方法则是通过向 sysfs 文件 sriov_numvfs 写入值来启用或禁用与某个 PCIe PF 关联的 VF。
相比第一种方法（其作用范围是同型号的所有 PF），这种方式支持按每个 PF 单独设置 VF 的启用/禁用数量。

此外，PCI SR-IOV 核心支持还会确保启用/禁用操作的合法性，从而减少各个驱动中重复编写相同的校验逻辑（例如：启用 VF 时检查 numvfs == 0，或确保 numvfs <= totalvfs）。

推荐为新的/未来的 VF 设备使用第二种方法。

How can I use the Virtual Functions
-----------------------------------

VF（虚拟功能）在内核中被视为热插拔的 PCI 设备，因此它们应当能够像真实的 PCI 设备一样工作。
VF 需要的设备驱动程序与普通 PCI 设备所需的驱动程序是相同的。

Developer Guide
===============

SR-IOV API
----------

启用 SR-IOV 功能的方法如下：

（a）第一种方法：在驱动程序中调用：

	int pci_enable_sriov(struct pci_dev *dev, int nr_virtfn);

其中 nr_virtfn 是要启用的虚拟功能（VF）数量。

(b) 第二种方法：通过 sysfs 接口：

	echo 'nr_virtfn' > /sys/bus/pci/devices/<DOMAIN:BUS:DEVICE.FUNCTION>/sriov_numvfs

禁用 SR-IOV 功能的方法如下：

(a) 第一种方法：在驱动程序中调用：

	void pci_disable_sriov(struct pci_dev *dev);

（b）第二种方法：通过 sysfs 接口：

	echo  0 > /sys/bus/pci/devices/<DOMAIN:BUS:DEVICE.FUNCTION>/sriov_numvfs

若要启用宿主机上兼容驱动程序对 VF 的自动探测（默认行为），可在启用 SR-IOV 功能之前运行以下命令：
::

	echo 1 > /sys/bus/pci/devices/<DOMAIN:BUS:DEVICE.FUNCTION>/sriov_drivers_autoprobe

若要禁用宿主机上兼容驱动程序对 VF 的自动探测，可在启用 SR-IOV 功能之前运行以下命令。注意：修改此项不会影响已被探测的 VF。
::

	echo  0 > /sys/bus/pci/devices/<DOMAIN:BUS:DEVICE.FUNCTION>/sriov_drivers_autoprobe


Usage example
-------------

下面的代码片段展示了 SR-IOV API 的使用方法
::

	static int dev_probe(struct pci_dev *dev, const struct pci_device_id *id)
	{
		pci_enable_sriov(dev, NR_VIRTFN);

		...

		return 0;
	}

	static void dev_remove(struct pci_dev *dev)
	{
		pci_disable_sriov(dev);

		...
	}

	static int dev_suspend(struct pci_dev *dev, pm_message_t state)
	{
		...

		return 0;
	}

	static int dev_resume(struct pci_dev *dev)
	{
		...

		return 0;
	}

	static void dev_shutdown(struct pci_dev *dev)
	{
		...
	}

	static int dev_sriov_configure(struct pci_dev *dev, int numvfs)
	{
		if (numvfs > 0) {
			...
			pci_enable_sriov(dev, numvfs);
			...
			return numvfs;
		}
		if (numvfs == 0) {
			....
			pci_disable_sriov(dev);
			...
			return 0;
		}
	}

	static struct pci_driver dev_driver = {
		.name =		"SR-IOV Physical Function driver",
		.id_table =	dev_id_table,
		.probe =	dev_probe,
		.remove =	dev_remove,
		.suspend =	dev_suspend,
		.resume =	dev_resume,
		.shutdown =	dev_shutdown,
		.sriov_configure = dev_sriov_configure,
	};
