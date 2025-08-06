.. SPDX-License-Identifier: GPL-2.0

============================================
Accessing PCI device resources through sysfs
============================================

sysfs, 通常挂载在 /sys, 在支持的系统平台上提供对 PCI 资源的访问, 例如，一个特定的总线可能看起来像这样::

     /sys/devices/pci0000:17
     |-- 0000:17:00.0
     |   |-- class
     |   |-- config
     |   |-- device
     |   |-- enable
     |   |-- irq
     |   |-- local_cpus
     |   |-- remove
     |   |-- resource
     |   |-- resource0
     |   |-- resource1
     |   |-- resource2
     |   |-- revision
     |   |-- rom
     |   |-- subsystem_device
     |   |-- subsystem_vendor
     |   `-- vendor
     `-- ...

最上层的元素描述了 PCI 的 域号(domain)和总线号(bus number). 在这个例子中, 域号是 0000, 总线号是 17(这两个值都是十六进制表示).
这个总线包含一个位于槽位 0(slot 0)的单功能设备. 为了方便起见，域号和总线号 会在路径中重复出现.
在该设备对应的目录下, 每个文件都有其各自的功能

       =================== =====================================================
       file		   function
       =================== =====================================================
       class		   PCI class (ascii, ro)
       config		   PCI config space (binary, rw)
       device		   PCI device (ascii, ro)
       enable	           Whether the device is enabled (ascii, rw)
       irq		   IRQ number (ascii, ro)
       local_cpus	   nearby CPU mask (cpumask, ro)
       remove		   remove device from kernel's list (ascii, wo)
       resource		   PCI resource host addresses (ascii, ro)
       resource0..N	   PCI resource N, if present (binary, mmap, rw\ [1]_)
       resource0_wc..N_wc  PCI WC map resource N, if prefetchable (binary, mmap)
       revision		   PCI revision (ascii, ro)
       rom		   PCI ROM resource, if present (binary, ro)
       subsystem_device	   PCI subsystem device (ascii, ro)
       subsystem_vendor	   PCI subsystem vendor (ascii, ro)
       vendor		   PCI vendor (ascii, ro)
       =================== =====================================================

::

  ro - read only file
  rw - file is readable and writable
  wo - write only file
  mmap - file is mmapable
  ascii - file contains ascii text
  binary - file contains binary data
  cpumask - file contains a cpumask type

.. [1] rw for IORESOURCE_IO (I/O port) regions only

只读文件是用于提供信息的, 对它们的写操作将被忽略, 唯一的例外是 'rom' 文件.  
可写文件可用于对设备执行操作(例如: 更改配置空间, 卸载设备)
支持 mmap 的文件可以通过从偏移量 0 开始对该文件进行 mmap, 从而用于在用户空间对设备进行实际编程.
请注意, 一些平台不支持对某些资源进行mmap, 因此请务必检查任何尝试执行的 mmap 调用的返回值
最典型的不支持 mmap 的资源是 I/O 端口资源, 但这些资源仍然支持 read 和 write 访问

'enable' 文件提供了一个计数器, 用于指示该设备被启用的次数
如果当前 enable 文件返回值为 4, 并向其中 echo 一个 1, 那么它将返回 5.
向其中 echo 一个 0 会使计数减少, 不过，即使它的值减到 0, 一些初始化操作可能不会被撤销

rom 文件是一个特殊文件，它在设备支持的情况下，提供对设备 ROM 的只读访问
但它默认是禁用的，因此在尝试读取之前，应用程序应该先向该文件写入字符串 "1" 以启用它，读取完成后，再向该文件写入 "0" 来将其禁用。
注意, 设备必须处于启用状态, rom 读取操作才能成功返回数据。
如果该设备尚未绑定驱动程序，可以通过上面描述的 enable 文件来启用该设备

remove 文件用于移除 PCI 设备，只需向该文件写入一个非零整数即可
这不涉及任何热插拔功能，例如关闭设备电源
该操作会将设备从内核的 PCI 设备列表中移除，对应的 sysfs 目录也会被删除，同时设备也会从任何绑定的驱动程序中解绑。
不允许移除 PCI 根总线(root bus)

通过 sysfs 访问传统资源
----------------------------------------

如果底层平台支持，传统的 I/O 端口和 ISA 内存资源也会通过 sysfs 提供。
它们位于 PCI 类层级结构中，例如：

	/sys/class/pci_bus/0000:17/
	|-- bridge -> ../../../devices/pci0000:17
	|-- cpuaffinity
	|-- legacy_io
	`-- legacy_mem

legacy_io 文件是一个可读写的文件，应用程序可以通过它进行传统的端口 I/O 操作
应用程序应打开该文件, seek 到目标端口(例如 0x3e8),然后读取或写入 1、2 或 4 字节的数据
legacy_mem 文件则应通过 mmap 映射，偏移量应对应所需的内存地址偏移，
例如 0xa0000 表示 VGA 帧缓冲区。
随后，应用程序可以直接解引用返回的指针（当然，在此之前应检查是否存在错误），以访问传统的内存空间。

在新平台上支持 PCI 访问
--------------------------------------

为了支持上述所描述的 PCI 资源映射, Linux 平台代码理想情况下应定义 ARCH_GENERIC_PCI_MMAP_RESOURCE, 并使用该功能的通用实现。
为了支持通过 /proc/bus/pci 文件执行 mmap() 的历史接口，平台也可以设置 HAVE_PCI_MMAP。

另外，设置了 HAVE_PCI_MMAP 的平台也可以选择自行实现 pci_mmap_page_range()，而不是定义 ARCH_GENERIC_PCI_MMAP_RESOURCE。

支持对 PCI 资源进行 写合并(write-combining)映射 的平台，必须定义函数 arch_can_pci_mmap_wc()，该函数在运行时返回非零值表示允许写合并。

支持对 I/O 类型资源进行映射 的平台，也应类似地定义 arch_can_pci_mmap_io() 函数。

对于传统资源(legacy resources), 其支持由宏 HAVE_PCI_LEGACY 控制。
希望支持传统功能的平台应定义该宏，并提供以下函数的实现：
  •	pci_legacy_read
	•	pci_legacy_write
	•	pci_mmap_legacy_page_range
