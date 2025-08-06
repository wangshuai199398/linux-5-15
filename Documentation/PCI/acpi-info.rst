.. SPDX-License-Identifier: GPL-2.0

========================================
ACPI considerations for PCI host bridges
========================================

总的原则是，除非操作系统可以通过其他方式发现硬件，否则 ACPI 命名空间必须描述操作系统可能使用的所有内容【1, 2】。

例如，标准硬件机制无法枚举 PCI 主桥，因此 ACPI 命名空间必须描述每个主桥、访问该主桥下 PCI 配置空间的方法、主桥转发到 PCI 的地址空间窗口（通过 _CRS）以及传统 INTx 中断的路由（通过 _PRT）。

位于主桥下的 PCI 设备通常不需要通过 ACPI 描述。
操作系统可以使用标准的 PCI 枚举机制（通过配置访问）发现和识别设备，并读取和分配它们的 BAR。
但在某些情况下，如果 ACPI 提供电源管理或热插拔功能，或者设备的 INTx 中断连接到平台中断控制器并且需要 _PRT 描述这些连接，那么 ACPI 也可以描述这些设备。

ACPI 资源描述是通过 ACPI 命名空间中设备的 _CRS 对象完成的【2】。
_CRS 类似于通用的 PCI BAR：即使操作系统没有对应驱动程序，也可以读取 _CRS 了解该设备使用了哪些资源【3】。
这非常重要，因为这意味着旧操作系统也能在存在新设备的系统上正常运行。
虽然新设备可能无法正常工作，但操作系统至少可以确保不会出现资源冲突。

诸如 MCFG、HPET、ECDT 等静态表 不 是用于保留地址空间的机制。
这些静态表用于操作系统在引导早期、还无法解析 ACPI 命名空间时获取所需信息。
如果定义了一个新表，而旧系统忽略它，也必须能够正常运行。
_CRS 能实现这一点，因为它是通用的，并且能被旧操作系统识别；静态表则不行。

如果期望操作系统管理一个无法自动发现的、通过 ACPI 描述的设备，该设备将包含特定的 _HID / _CID 来告诉操作系统应绑定哪个驱动程序，而 _CRS 则向操作系统和驱动程序说明设备寄存器的位置。

PCI 主桥是 PNP0A03 或 PNP0A08 设备。它们的 _CRS 应描述它们消耗的所有地址空间，包括：
  •	主桥转发到 PCI 总线的所有窗口；
  •	主桥本身不转发到 PCI 的寄存器（如用于设置子总线范围的寄存器、窗口寄存器等）；
  •	这类寄存器是设备特定的，因此 PNP0A03/PNP0A08 驱动程序只能通过 _PRS / _CRS / _SRS 管理它们；
  •	也包括 ECAM 空间（由主桥消费）；

ACPI 通过“Consumer/Producer”位来区分主桥寄存器（Consumer）和主桥窗口（Producer）【4, 5】，但早期 BIOS 并未正确使用该位。
因此，当前 ACPI 规范规定只对扩展地址空间描述符使用 Consumer/Producer，而旧的 QWord/DWord/Word 描述符中该位应被忽略。
因此，操作系统必须假设所有 QWord/DWord/Word 描述符都是窗口。

在引入扩展地址空间描述符之前，由于 Consumer/Producer 位失效，无法在 PNP0A03/PNP0A08 设备中描述主桥寄存器。
解决方法是在 PNP0C02（通用）设备中描述主桥寄存器（包括 ECAM）【6】。
除了 ECAM，主桥寄存器空间本身就是设备特定的，因此通用 PNP0A03/PNP0A08 驱动（如 pci_root.c）无需了解这些内容。


新架构应能在 PNP0A03 设备中使用扩展地址空间描述符中的 “Consumer” 类型来描述主桥寄存器（包括 ECAM），尽管【6】中严格的解释可能不允许这样做。
但旧的 x86 和 ia64 内核会假设所有地址空间描述符（即使是“Consumer”类型）都是窗口，因此在这些架构上以这种方式描述主桥寄存器并不安全。

PNP0C02 “主板”设备本质上是一种兜底手段。它们没有明确的编程模型，唯一的含义是“不要将这些资源用于其他用途”。因此，PNP0C02 的 _CRS 应声明所有符合以下条件的地址空间：
  1. 没有被 ACPI 命名空间中任何其他设备的 _CRS 声明；
  2. 不应被操作系统分配给其他用途。

PCIe 规范要求除非有标准固件接口（如 ia64 的 SAL 接口）用于配置访问，否则必须使用增强配置访问机制（ECAM）【7】。
主桥将 ECAM 的内存地址空间转换为 PCI 配置访问。ECAM 地址空间的布局和功能由规范定义，只有地址基址是设备特定的。
ACPI 操作系统可以通过静态 MCFG 表或 PNP0A03 设备中的 _CBA 方法获取地址基址。
  •	对于不可热插拔的主桥，MCFG 表必须描述其 ECAM 空间【8】；
  •	对于热插拔主桥，必须通过 _CBA 方法 在 PNP0A03 设备中描述 ECAM 空间【9】；
  •	无论是通过 MCFG 还是 _CBA，基地址都表示总线号为 0 的地址空间，即使该桥下面的总线范围（由 _CRS 报告）不从 0 开始。


[1] ACPI 6.2, sec 6.1:
    For any device that is on a non-enumerable type of bus (for example, an
    ISA bus), OSPM enumerates the devices' identifier(s) and the ACPI
    system firmware must supply an _HID object ... for each device to
    enable OSPM to do that.

[2] ACPI 6.2, sec 3.7:
    The OS enumerates motherboard devices simply by reading through the
    ACPI Namespace looking for devices with hardware IDs.

    Each device enumerated by ACPI includes ACPI-defined objects in the
    ACPI Namespace that report the hardware resources the device could
    occupy [_PRS], an object that reports the resources that are currently
    used by the device [_CRS], and objects for configuring those resources
    [_SRS].  The information is used by the Plug and Play OS (OSPM) to
    configure the devices.

[3] ACPI 6.2, sec 6.2:
    OSPM uses device configuration objects to configure hardware resources
    for devices enumerated via ACPI.  Device configuration objects provide
    information about current and possible resource requirements, the
    relationship between shared resources, and methods for configuring
    hardware resources.

    When OSPM enumerates a device, it calls _PRS to determine the resource
    requirements of the device.  It may also call _CRS to find the current
    resource settings for the device.  Using this information, the Plug and
    Play system determines what resources the device should consume and
    sets those resources by calling the device’s _SRS control method.

    In ACPI, devices can consume resources (for example, legacy keyboards),
    provide resources (for example, a proprietary PCI bridge), or do both.
    Unless otherwise specified, resources for a device are assumed to be
    taken from the nearest matching resource above the device in the device
    hierarchy.

[4] ACPI 6.2, sec 6.4.3.5.1, 2, 3, 4:
    QWord/DWord/Word Address Space Descriptor (.1, .2, .3)
      General Flags: Bit [0] Ignored

    Extended Address Space Descriptor (.4)
      General Flags: Bit [0] Consumer/Producer:

        * 1 – This device consumes this resource
        * 0 – This device produces and consumes this resource

[5] ACPI 6.2, sec 19.6.43:
    ResourceUsage specifies whether the Memory range is consumed by
    this device (ResourceConsumer) or passed on to child devices
    (ResourceProducer).  If nothing is specified, then
    ResourceConsumer is assumed.

[6] PCI Firmware 3.2, sec 4.1.2:
    If the operating system does not natively comprehend reserving the
    MMCFG region, the MMCFG region must be reserved by firmware.  The
    address range reported in the MCFG table or by _CBA method (see Section
    4.1.3) must be reserved by declaring a motherboard resource.  For most
    systems, the motherboard resource would appear at the root of the ACPI
    namespace (under \_SB) in a node with a _HID of EISAID (PNP0C02), and
    the resources in this case should not be claimed in the root PCI bus’s
    _CRS.  The resources can optionally be returned in Int15 E820 or
    EFIGetMemoryMap as reserved memory but must always be reported through
    ACPI as a motherboard resource.

[7] PCI Express 4.0, sec 7.2.2:
    For systems that are PC-compatible, or that do not implement a
    processor-architecture-specific firmware interface standard that allows
    access to the Configuration Space, the ECAM is required as defined in
    this section.

[8] PCI Firmware 3.2, sec 4.1.2:
    The MCFG table is an ACPI table that is used to communicate the base
    addresses corresponding to the non-hot removable PCI Segment Groups
    range within a PCI Segment Group available to the operating system at
    boot. This is required for the PC-compatible systems.

    The MCFG table is only used to communicate the base addresses
    corresponding to the PCI Segment Groups available to the system at
    boot.

[9] PCI Firmware 3.2, sec 4.1.3:
    The _CBA (Memory mapped Configuration Base Address) control method is
    an optional ACPI object that returns the 64-bit memory mapped
    configuration base address for the hot plug capable host bridge. The
    base address returned by _CBA is processor-relative address. The _CBA
    control method evaluates to an Integer.

    This control method appears under a host bridge object. When the _CBA
    method appears under an active host bridge object, the operating system
    evaluates this structure to identify the memory mapped configuration
    base address corresponding to the PCI Segment Group for the bus number
    range specified in _CRS method. An ACPI name space object that contains
    the _CBA method must also contain a corresponding _SEG method.
