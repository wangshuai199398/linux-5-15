// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 1995  Linus Torvalds
 *
 * This file contains the setup_arch() code, which handles the architecture-dependent
 * parts of early kernel initialization.
 */
#include <linux/acpi.h>
#include <linux/console.h>
#include <linux/crash_dump.h>
#include <linux/dma-map-ops.h>
#include <linux/dmi.h>
#include <linux/efi.h>
#include <linux/init_ohci1394_dma.h>
#include <linux/initrd.h>
#include <linux/iscsi_ibft.h>
#include <linux/memblock.h>
#include <linux/panic_notifier.h>
#include <linux/pci.h>
#include <linux/root_dev.h>
#include <linux/hugetlb.h>
#include <linux/tboot.h>
#include <linux/security.h>
#include <linux/usb/xhci-dbgp.h>
#include <linux/static_call.h>
#include <linux/swiotlb.h>

#include <uapi/linux/mount.h>

#include <xen/xen.h>

#include <asm/apic.h>
#include <asm/numa.h>
#include <asm/bios_ebda.h>
#include <asm/bugs.h>
#include <asm/cpu.h>
#include <asm/efi.h>
#include <asm/gart.h>
#include <asm/hypervisor.h>
#include <asm/io_apic.h>
#include <asm/kasan.h>
#include <asm/kaslr.h>
#include <asm/mce.h>
#include <asm/mtrr.h>
#include <asm/realmode.h>
#include <asm/olpc_ofw.h>
#include <asm/pci-direct.h>
#include <asm/prom.h>
#include <asm/proto.h>
#include <asm/thermal.h>
#include <asm/unwind.h>
#include <asm/vsyscall.h>
#include <linux/vmalloc.h>

/*
 * max_low_pfn_mapped: highest directly mapped pfn < 4 GB
 * max_pfn_mapped:     highest directly mapped pfn > 4 GB
 *
 * The direct mapping only covers E820_TYPE_RAM regions, so the ranges and gaps are
 * represented by pfn_mapped[].
 */
unsigned long max_low_pfn_mapped;
unsigned long max_pfn_mapped;

#ifdef CONFIG_DMI
RESERVE_BRK(dmi_alloc, 65536);
#endif


unsigned long _brk_start = (unsigned long)__brk_base;
unsigned long _brk_end   = (unsigned long)__brk_base;

struct boot_params boot_params;

/*
 * These are the four main kernel memory regions, we put them into
 * the resource tree so that kdump tools and other debugging tools
 * recover it:
 */

static struct resource rodata_resource = {
	.name	= "Kernel rodata",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM
};

static struct resource data_resource = {
	.name	= "Kernel data",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM
};

static struct resource code_resource = {
	.name	= "Kernel code",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM
};

static struct resource bss_resource = {
	.name	= "Kernel bss",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM
};


#ifdef CONFIG_X86_32
/* CPU data as detected by the assembly code in head_32.S */
struct cpuinfo_x86 new_cpu_data;

/* Common CPU data for all CPUs */
struct cpuinfo_x86 boot_cpu_data __read_mostly;
EXPORT_SYMBOL(boot_cpu_data);

unsigned int def_to_bigsmp;

struct apm_info apm_info;
EXPORT_SYMBOL(apm_info);

#if defined(CONFIG_X86_SPEEDSTEP_SMI) || \
	defined(CONFIG_X86_SPEEDSTEP_SMI_MODULE)
struct ist_info ist_info;
EXPORT_SYMBOL(ist_info);
#else
struct ist_info ist_info;
#endif

#else
struct cpuinfo_x86 boot_cpu_data __read_mostly;
EXPORT_SYMBOL(boot_cpu_data);
#endif


#if !defined(CONFIG_X86_PAE) || defined(CONFIG_X86_64)
__visible unsigned long mmu_cr4_features __ro_after_init;
#else
__visible unsigned long mmu_cr4_features __ro_after_init = X86_CR4_PAE;
#endif

/* Boot loader ID and version as integers, for the benefit of proc_dointvec */
int bootloader_type, bootloader_version;

/*
 * Setup options
 */
struct screen_info screen_info;
EXPORT_SYMBOL(screen_info);
struct edid_info edid_info;
EXPORT_SYMBOL_GPL(edid_info);

extern int root_mountflags;

unsigned long saved_video_mode;

#define RAMDISK_IMAGE_START_MASK	0x07FF
#define RAMDISK_PROMPT_FLAG		0x8000
#define RAMDISK_LOAD_FLAG		0x4000

static char __initdata command_line[COMMAND_LINE_SIZE];
#ifdef CONFIG_CMDLINE_BOOL
static char __initdata builtin_cmdline[COMMAND_LINE_SIZE] = CONFIG_CMDLINE;
#endif

#if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)
struct edd edd;
#ifdef CONFIG_EDD_MODULE
EXPORT_SYMBOL(edd);
#endif
/**
 * copy_edd() - Copy the BIOS EDD information
 *              from boot_params into a safe place.
 *
 */
static inline void __init copy_edd(void)
{
     memcpy(edd.mbr_signature, boot_params.edd_mbr_sig_buffer,
	    sizeof(edd.mbr_signature));
     memcpy(edd.edd_info, boot_params.eddbuf, sizeof(edd.edd_info));
     edd.mbr_signature_nr = boot_params.edd_mbr_sig_buf_entries;
     edd.edd_info_nr = boot_params.eddbuf_entries;
}
#else
static inline void __init copy_edd(void)
{
}
#endif
//扩展 brk 区段
void * __init extend_brk(size_t size, size_t align)
{
	size_t mask = align - 1;
	void *ret;

	BUG_ON(_brk_start == 0);
	BUG_ON(align & mask);

	_brk_end = (_brk_end + mask) & ~mask;
	BUG_ON((char *)(_brk_end + size) > __brk_limit);

	ret = (void *)_brk_end;
	_brk_end += size;

	memset(ret, 0, size);

	return ret;
}

#ifdef CONFIG_X86_32
static void __init cleanup_highmap(void)
{
}
#endif

static void __init reserve_brk(void)
{
	if (_brk_end > _brk_start)
		memblock_reserve(__pa_symbol(_brk_start),
				 _brk_end - _brk_start);

	/* Mark brk area as locked down and no longer taking any new allocations */
	//因为在这之后我们不会再为 brk 分配内存了，我们需要使用 cleanup_highmap 函数来释放内核映射中越界的内存区域
	_brk_start = 0;
}

u64 relocated_ramdisk;

#ifdef CONFIG_BLK_DEV_INITRD

static u64 __init get_ramdisk_image(void)
{
	u64 ramdisk_image = boot_params.hdr.ramdisk_image;

	ramdisk_image |= (u64)boot_params.ext_ramdisk_image << 32;

	if (ramdisk_image == 0)
		ramdisk_image = phys_initrd_start;

	return ramdisk_image;
}
static u64 __init get_ramdisk_size(void)
{
	u64 ramdisk_size = boot_params.hdr.ramdisk_size;

	ramdisk_size |= (u64)boot_params.ext_ramdisk_size << 32;

	if (ramdisk_size == 0)
		ramdisk_size = phys_initrd_size;

	return ramdisk_size;
}

static void __init relocate_initrd(void)
{
	/* Assume only end is not page aligned */
	u64 ramdisk_image = get_ramdisk_image();
	u64 ramdisk_size  = get_ramdisk_size();
	u64 area_size     = PAGE_ALIGN(ramdisk_size);

	/* We need to move the initrd down into directly mapped mem */
	relocated_ramdisk = memblock_phys_alloc_range(area_size, PAGE_SIZE, 0,
						      PFN_PHYS(max_pfn_mapped));
	if (!relocated_ramdisk)
		panic("Cannot find place for new RAMDISK of size %lld\n",
		      ramdisk_size);

	initrd_start = relocated_ramdisk + PAGE_OFFSET;
	initrd_end   = initrd_start + ramdisk_size;
	printk(KERN_INFO "Allocated new RAMDISK: [mem %#010llx-%#010llx]\n",
	       relocated_ramdisk, relocated_ramdisk + ramdisk_size - 1);

	copy_from_early_mem((void *)initrd_start, ramdisk_image, ramdisk_size);

	printk(KERN_INFO "Move RAMDISK from [mem %#010llx-%#010llx] to"
		" [mem %#010llx-%#010llx]\n",
		ramdisk_image, ramdisk_image + ramdisk_size - 1,
		relocated_ramdisk, relocated_ramdisk + ramdisk_size - 1);
}

//保留替换内核的text和data段用来初始化initrd
static void __init early_reserve_initrd(void)
{
	/* Assume only end is not page aligned */
	//获取RAM DISK的基地址、RAM DISK的大小以及RAM DISK的结束地址
	u64 ramdisk_image = get_ramdisk_image();
	u64 ramdisk_size  = get_ramdisk_size();
	u64 ramdisk_end   = PAGE_ALIGN(ramdisk_image + ramdisk_size);

	if (!boot_params.hdr.type_of_loader ||
	    !ramdisk_image || !ramdisk_size)
		return;		/* No initrd provided by bootloader */
	//并保留内存块将ramdisk传输到最终的内存地址，然后进行初始化
	memblock_reserve(ramdisk_image, ramdisk_end - ramdisk_image);
}
//首先确定 initrd 的基地址和结束地址，并检查 bootloader 是否提供了 initrd
static void __init reserve_initrd(void)
{
	/* Assume only end is not page aligned */
	u64 ramdisk_image = get_ramdisk_image();
	u64 ramdisk_size  = get_ramdisk_size();
	u64 ramdisk_end   = PAGE_ALIGN(ramdisk_image + ramdisk_size);

	if (!boot_params.hdr.type_of_loader ||
	    !ramdisk_image || !ramdisk_size)
		return;		/* No initrd provided by bootloader */

	initrd_start = 0;

	printk(KERN_INFO "RAMDISK: [mem %#010llx-%#010llx]\n", ramdisk_image,
			ramdisk_end - 1);

	if (pfn_range_is_mapped(PFN_DOWN(ramdisk_image),
				PFN_DOWN(ramdisk_end))) {
		/* All are mapped, easy case */
		initrd_start = ramdisk_image + PAGE_OFFSET;
		initrd_end = initrd_start + ramdisk_size;
		return;
	}

	relocate_initrd();
	//释放原 RAM 磁盘占用的 memblock 内存
	memblock_free(ramdisk_image, ramdisk_end - ramdisk_image);
}

#else
static void __init early_reserve_initrd(void)
{
}
static void __init reserve_initrd(void)
{
}
#endif /* CONFIG_BLK_DEV_INITRD */

static void __init parse_setup_data(void)
{
	struct setup_data *data;
	u64 pa_data, pa_next;

	pa_data = boot_params.hdr.setup_data;
	while (pa_data) {
		u32 data_len, data_type;

		data = early_memremap(pa_data, sizeof(*data));
		data_len = data->len + sizeof(struct setup_data);
		data_type = data->type;
		pa_next = data->next;
		early_memunmap(data, sizeof(*data));

		switch (data_type) {
		case SETUP_E820_EXT:
			e820__memory_setup_extended(pa_data, data_len);
			break;
		case SETUP_DTB:
			add_dtb(pa_data);
			break;
		case SETUP_EFI:
			parse_efi_setup(pa_data, data_len);
			break;
		default:
			break;
		}
		pa_data = pa_next;
	}
}

static void __init memblock_x86_reserve_range_setup_data(void)
{
	struct setup_indirect *indirect;
	struct setup_data *data;
	u64 pa_data, pa_next;
	u32 len;

	pa_data = boot_params.hdr.setup_data;
	while (pa_data) {
		data = early_memremap(pa_data, sizeof(*data));
		if (!data) {
			pr_warn("setup: failed to memremap setup_data entry\n");
			return;
		}

		len = sizeof(*data);
		pa_next = data->next;

		memblock_reserve(pa_data, sizeof(*data) + data->len);

		if (data->type == SETUP_INDIRECT) {
			len += data->len;
			early_memunmap(data, sizeof(*data));
			data = early_memremap(pa_data, len);
			if (!data) {
				pr_warn("setup: failed to memremap indirect setup_data\n");
				return;
			}

			indirect = (struct setup_indirect *)data->data;

			if (indirect->type != SETUP_INDIRECT)
				memblock_reserve(indirect->addr, indirect->len);
		}

		pa_data = pa_next;
		early_memunmap(data, len);
	}
}

/*
 * --------- Crashkernel reservation ------------------------------
 */

#ifdef CONFIG_KEXEC_CORE

/* 16M alignment for crash kernel regions */
#define CRASH_ALIGN		SZ_16M

/*
 * Keep the crash kernel below this limit.
 *
 * Earlier 32-bits kernels would limit the kernel to the low 512 MB range
 * due to mapping restrictions.
 *
 * 64-bit kdump kernels need to be restricted to be under 64 TB, which is
 * the upper limit of system RAM in 4-level paging mode. Since the kdump
 * jump could be from 5-level paging to 4-level paging, the jump will fail if
 * the kernel is put above 64 TB, and during the 1st kernel bootup there's
 * no good way to detect the paging mode of the target kernel which will be
 * loaded for dumping.
 */
#ifdef CONFIG_X86_32
# define CRASH_ADDR_LOW_MAX	SZ_512M
# define CRASH_ADDR_HIGH_MAX	SZ_512M
#else
# define CRASH_ADDR_LOW_MAX	SZ_4G
# define CRASH_ADDR_HIGH_MAX	SZ_64T
#endif

static int __init reserve_crashkernel_low(void)
{
#ifdef CONFIG_X86_64
	unsigned long long base, low_base = 0, low_size = 0;
	unsigned long low_mem_limit;
	int ret;

	low_mem_limit = min(memblock_phys_mem_size(), CRASH_ADDR_LOW_MAX);

	/* crashkernel=Y,low */
	ret = parse_crashkernel_low(boot_command_line, low_mem_limit, &low_size, &base);
	if (ret) {
		/*
		 * two parts from kernel/dma/swiotlb.c:
		 * -swiotlb size: user-specified with swiotlb= or default.
		 *
		 * -swiotlb overflow buffer: now hardcoded to 32k. We round it
		 * to 8M for other buffers that may need to stay low too. Also
		 * make sure we allocate enough extra low memory so that we
		 * don't run out of DMA buffers for 32-bit devices.
		 */
		low_size = max(swiotlb_size_or_default() + (8UL << 20), 256UL << 20);
	} else {
		/* passed with crashkernel=0,low ? */
		if (!low_size)
			return 0;
	}
	//申请内存
	low_base = memblock_phys_alloc_range(low_size, CRASH_ALIGN, 0, CRASH_ADDR_LOW_MAX);
	if (!low_base) {
		pr_err("Cannot reserve %ldMB crashkernel low memory, please try smaller size.\n",
		       (unsigned long)(low_size >> 20));
		return -ENOMEM;
	}

	pr_info("Reserving %ldMB of low memory at %ldMB for crashkernel (low RAM limit: %ldMB)\n",
		(unsigned long)(low_size >> 20),
		(unsigned long)(low_base >> 20),
		(unsigned long)(low_mem_limit >> 20));

	crashk_low_res.start = low_base;
	crashk_low_res.end   = low_base + low_size - 1;
	insert_resource(&iomem_resource, &crashk_low_res);
#endif
	return 0;
}

static void __init reserve_crashkernel(void)
{
	unsigned long long crash_size, crash_base, total_mem;
	bool high = false;
	int ret;

	total_mem = memblock_phys_mem_size();

	/* crashkernel=XM */
	ret = parse_crashkernel(boot_command_line, total_mem, &crash_size, &crash_base);
	if (ret != 0 || crash_size <= 0) {
		/* crashkernel=X,high */
		ret = parse_crashkernel_high(boot_command_line, total_mem,
					     &crash_size, &crash_base);
		if (ret != 0 || crash_size <= 0)
			return;
		high = true;
	}

	if (xen_pv_domain()) {
		pr_info("Ignoring crashkernel for a Xen PV domain\n");
		return;
	}

	/* 0 means: find the address automatically */
	if (!crash_base) {
		/*
		 * Set CRASH_ADDR_LOW_MAX upper bound for crash memory,
		 * crashkernel=x,high reserves memory over 4G, also allocates
		 * 256M extra low memory for DMA buffers and swiotlb.
		 * But the extra memory is not required for all machines.
		 * So try low memory first and fall back to high memory
		 * unless "crashkernel=size[KMG],high" is specified.
		 */
		if (!high)
			crash_base = memblock_phys_alloc_range(crash_size,
						CRASH_ALIGN, CRASH_ALIGN,
						CRASH_ADDR_LOW_MAX);
		if (!crash_base)
			crash_base = memblock_phys_alloc_range(crash_size,
						CRASH_ALIGN, CRASH_ALIGN,
						CRASH_ADDR_HIGH_MAX);
		if (!crash_base) {
			pr_info("crashkernel reservation failed - No suitable area found.\n");
			return;
		}
	} else {
		unsigned long long start;

		start = memblock_phys_alloc_range(crash_size, SZ_1M, crash_base,
						  crash_base + crash_size);
		if (start != crash_base) {
			pr_info("crashkernel reservation failed - memory is in use.\n");
			return;
		}
	}

	if (crash_base >= (1ULL << 32) && reserve_crashkernel_low()) {
		memblock_free(crash_base, crash_size);
		return;
	}

	pr_info("Reserving %ldMB of memory at %ldMB for crashkernel (System RAM: %ldMB)\n",
		(unsigned long)(crash_size >> 20),
		(unsigned long)(crash_base >> 20),
		(unsigned long)(total_mem >> 20));

	crashk_res.start = crash_base;
	crashk_res.end   = crash_base + crash_size - 1;
	insert_resource(&iomem_resource, &crashk_res);
}
#else
static void __init reserve_crashkernel(void)
{
}
#endif

static struct resource standard_io_resources[] = {
	{ .name = "dma1", .start = 0x00, .end = 0x1f,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "pic1", .start = 0x20, .end = 0x21,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "timer0", .start = 0x40, .end = 0x43,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "timer1", .start = 0x50, .end = 0x53,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "keyboard", .start = 0x60, .end = 0x60,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "keyboard", .start = 0x64, .end = 0x64,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "dma page reg", .start = 0x80, .end = 0x8f,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "pic2", .start = 0xa0, .end = 0xa1,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "dma2", .start = 0xc0, .end = 0xdf,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "fpu", .start = 0xf0, .end = 0xff,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO }
};

void __init reserve_standard_io_resources(void)
{
	int i;

	/* request I/O space for devices used on all i[345]86 PCs */
	for (i = 0; i < ARRAY_SIZE(standard_io_resources); i++)
		request_resource(&ioport_resource, &standard_io_resources[i]);

}

static bool __init snb_gfx_workaround_needed(void)
{
#ifdef CONFIG_PCI
	int i;
	u16 vendor, devid;
	static const __initconst u16 snb_ids[] = {
		0x0102,
		0x0112,
		0x0122,
		0x0106,
		0x0116,
		0x0126,
		0x010a,
	};

	/* Assume no if something weird is going on with PCI */
	if (!early_pci_allowed())
		return false;

	vendor = read_pci_config_16(0, 2, 0, PCI_VENDOR_ID);
	if (vendor != 0x8086)
		return false;

	devid = read_pci_config_16(0, 2, 0, PCI_DEVICE_ID);
	for (i = 0; i < ARRAY_SIZE(snb_ids); i++)
		if (devid == snb_ids[i])
			return true;
#endif

	return false;
}

/*
 * Sandy Bridge graphics has trouble with certain ranges, exclude
 * them from allocation.
 */
static void __init trim_snb_memory(void)
{
	static const __initconst unsigned long bad_pages[] = {
		0x20050000,
		0x20110000,
		0x20130000,
		0x20138000,
		0x40004000,
	};
	int i;

	if (!snb_gfx_workaround_needed())
		return;

	printk(KERN_DEBUG "reserving inaccessible SNB gfx pages\n");

	/*
	 * SandyBridge integrated graphics devices have a bug that prevents
	 * them from accessing certain memory ranges, namely anything below
	 * 1M and in the pages listed in bad_pages[] above.
	 *
	 * To avoid these pages being ever accessed by SNB gfx devices reserve
	 * bad_pages that have not already been reserved at boot time.
	 * All memory below the 1 MB mark is anyway reserved later during
	 * setup_arch(), so there is no need to reserve it here.
	 */

	for (i = 0; i < ARRAY_SIZE(bad_pages); i++) {
		if (memblock_reserve(bad_pages[i], PAGE_SIZE))
			printk(KERN_WARNING "failed to reserve 0x%08lx\n",
			       bad_pages[i]);
	}
}

static void __init trim_bios_range(void)
{
	/*
	 * A special case is the first 4Kb of memory;
	 * This is a BIOS owned area, not kernel ram, but generally
	 * not listed as such in the E820 table.
	 *
	 * This typically reserves additional memory (64KiB by default)
	 * since some BIOSes are known to corrupt low memory.  See the
	 * Kconfig help text for X86_RESERVE_LOW.
	 */
	e820__range_update(0, PAGE_SIZE, E820_TYPE_RAM, E820_TYPE_RESERVED);

	/*
	 * special case: Some BIOSes report the PC BIOS
	 * area (640Kb -> 1Mb) as RAM even though it is not.
	 * take them out.
	 */
	e820__range_remove(BIOS_BEGIN, BIOS_END - BIOS_BEGIN, E820_TYPE_RAM, 1);

	e820__update_table(e820_table);
}

/* called before trim_bios_range() to spare extra sanitize */
static void __init e820_add_kernel_range(void)
{
	u64 start = __pa_symbol(_text);
	u64 size = __pa_symbol(_end) - start;

	/*
	 * Complain if .text .data and .bss are not marked as E820_TYPE_RAM and
	 * attempt to fix it by adding the range. We may have a confused BIOS,
	 * or the user may have used memmap=exactmap or memmap=xxM$yyM to
	 * exclude kernel range. If we really are running on top non-RAM,
	 * we will crash later anyways.
	 */
	if (e820__mapped_all(start, start + size, E820_TYPE_RAM))
		return;

	pr_warn(".text .data .bss are not marked as E820_TYPE_RAM!\n");
	e820__range_remove(start, size, E820_TYPE_RAM, 0);
	e820__range_add(start, size, E820_TYPE_RAM);
}

static void __init early_reserve_memory(void)
{
	/*
	 * Reserve the memory occupied by the kernel between _text and
	 * __end_of_kernel_reserve symbols. Any kernel sections after the
	 * __end_of_kernel_reserve symbol must be explicitly reserved with a
	 * separate memblock_reserve() or they will be discarded.
	 */
	memblock_reserve(__pa_symbol(_text),
			 (unsigned long)__end_of_kernel_reserve - (unsigned long)_text);

	/*
	 * The first 4Kb of memory is a BIOS owned area, but generally it is
	 * not listed as such in the E820 table.
	 *
	 * Reserve the first 64K of memory since some BIOSes are known to
	 * corrupt low memory. After the real mode trampoline is allocated the
	 * rest of the memory below 640k is reserved.
	 *
	 * In addition, make sure page 0 is always reserved because on
	 * systems with L1TF its contents can be leaked to user processes.
	 */
	memblock_reserve(0, SZ_64K);

	early_reserve_initrd();
	//为 setup_data 重新映射内存并保留内存块
	memblock_x86_reserve_range_setup_data();

	reserve_ibft_region();
	reserve_bios_regions();
	trim_snb_memory();
}

/*
 * Dump out kernel offset information on panic.
 */
static int
dump_kernel_offset(struct notifier_block *self, unsigned long v, void *p)
{
	if (kaslr_enabled()) {
		pr_emerg("Kernel Offset: 0x%lx from 0x%lx (relocation range: 0x%lx-0x%lx)\n",
			 kaslr_offset(),
			 __START_KERNEL,
			 __START_KERNEL_map,
			 MODULES_VADDR-1);
	} else {
		pr_emerg("Kernel Offset: disabled\n");
	}

	return 0;
}

/*
 * 判断我们是否是由 EFI 引导程序加载的。如果是，那么我们也被传递了 EFI 的内存映射（efi memmap）、系统表（systab）等数据，
 * 因此我们在初始化时应该使用这些数据结构。
 * 注意：是否走 EFI 初始化路径由全局变量 efi_enabled 决定。
 * 这样就允许同一个内核镜像同时兼容：
 * 	使用传统 BIOS 的系统
 * 	使用 EFI 的系统
 */
/*
 * setup_arch —— 架构相关的启动初始化函数
 *
 * 注意：在 x86_64 架构上，即使在调用这个函数之前，fixmap（固定映射区）就已经准备好了
 * 
 * EFI（Extensible Firmware Interface）：现代系统的引导方式，替代传统 BIOS。
 * fixmap：内核在早期引导阶段使用的一段固定虚拟地址区域，用于映射某些特殊用途的内存（如 ACPI、页表、I/O 区域等）。
 */

void __init setup_arch(char **cmdline_p)
{
#ifdef CONFIG_X86_32
	memcpy(&boot_cpu_data, &new_cpu_data, sizeof(new_cpu_data));

	/*
	 * copy kernel address range established so far and switch
	 * to the proper swapper page table
	 */
	clone_pgd_range(swapper_pg_dir     + KERNEL_PGD_BOUNDARY,
			initial_page_table + KERNEL_PGD_BOUNDARY,
			KERNEL_PGD_PTRS);

	load_cr3(swapper_pg_dir);
	/*
	 * Note: Quark X1000 CPUs advertise PGE incorrectly and require
	 * a cr3 based tlb flush, so the following __flush_tlb_all()
	 * will not flush anything because the CPU quirk which clears
	 * X86_FEATURE_PGE has not been invoked yet. Though due to the
	 * load_cr3() above the TLB has been flushed already. The
	 * quirk is invoked before subsequent calls to __flush_tlb_all()
	 * so proper operation is guaranteed.
	 */
	__flush_tlb_all();
#else
	printk(KERN_INFO "Command line: %s\n", boot_command_line);//Command line: BOOT_IMAGE=/vmlinuz-5.15.178+ root=/dev/mapper/ubuntu--vg-ubuntu--lv ro debug systemd.log_level=debug systemd.log_target=console
	boot_cpu_data.x86_phys_bits = MAX_PHYSMEM_BITS;
#endif

	/* 如果我们运行在 OLPC（One Laptop Per Child）平台上的 OFW（Open Firmware）环境中，
	 * 那么由于 reserve_top() 的调用，可能会导致 fixmap（固定映射区）被重新定位。
	 * 因此，在访问 ioremap 区域之前，要先执行这一步操作 */
	olpc_ofw_detect();

	idt_setup_early_traps();
	early_cpu_init();
	jump_label_init();
	static_call_init();
	early_ioremap_init();

	setup_olpc_ofw_pgd();
	//获取根设备的主次设备号
	ROOT_DEV = old_decode_dev(boot_params.hdr.root_dev);
	screen_info = boot_params.screen_info;
	edid_info = boot_params.edid_info;
#ifdef CONFIG_X86_32
	apm_info.bios = boot_params.apm_bios_info;
	ist_info = boot_params.ist_info;
#endif
	saved_video_mode = boot_params.hdr.vid_mode;
	bootloader_type = boot_params.hdr.type_of_loader;
	if ((bootloader_type >> 4) == 0xe) {
		bootloader_type &= 0xf;
		bootloader_type |= (boot_params.hdr.ext_loader_type+0x10) << 4;
	}
	bootloader_version  = bootloader_type & 0xf;
	bootloader_version |= boot_params.hdr.ext_loader_ver << 4;

#ifdef CONFIG_BLK_DEV_RAM
	rd_image_start = boot_params.hdr.ram_size & RAMDISK_IMAGE_START_MASK;
#endif
#ifdef CONFIG_EFI
	if (!strncmp((char *)&boot_params.efi_info.efi_loader_signature,
		     EFI32_LOADER_SIGNATURE, 4)) {
		set_bit(EFI_BOOT, &efi.flags);
	} else if (!strncmp((char *)&boot_params.efi_info.efi_loader_signature,
		     EFI64_LOADER_SIGNATURE, 4)) {
		set_bit(EFI_BOOT, &efi.flags);
		set_bit(EFI_64BIT, &efi.flags);
	}
#endif

	x86_init.oem.arch_setup();

	/*
	 * 在将内存加入 memblock 之前，先进行一些内存保留操作，这样可以防止后续的 memblock 分配过程覆盖这些关键区域。
	 *
	 * 从这一步开始，凡是启动加载器（boot loader）、固件（firmware）或内核文本（kernel text）中仍然需要保留的内容，
	 * 要么通过 早期保留机制（early reserved），要么在 E820 表中标记为非 RAM（not RAM）。
	 * 除此之外的所有内存，内核就可以自由使用了。
	 *
	 * 这一步的调用必须发生在 e820__memory_setup() 之前，因为在 Xen 的 dom0（宿主域）上，e820__memory_setup() 
	 * 会调用 xen_memory_setup()，而后者依赖于这些早期内存保留操作已经完成。
	 * memblock：Linux 在早期内核启动阶段用于管理物理内存的分配器（比页分配器更早启用）；
	 * early reserved：在系统初始化早期就标记为“保留”的内存区域，防止被误用；
	 * E820 表：BIOS 或 UEFI 提供的内存分布表；
	 * not RAM：在 E820 中表示该区域不是普通可用内存；
	 * Xen dom0：Xen 虚拟化系统中的宿主系统（控制虚拟机的主操作系统）；
	 * xen_memory_setup()：Xen 平台特有的内存初始化函数，它依赖内核已知哪些区域被保留。
	 */
	early_reserve_memory();

	iomem_resource.end = (1ULL << boot_cpu_data.x86_phys_bits) - 1;
	//保存物理内存检测结果
	e820__memory_setup();
	//解析 setup_data，并且把 BIOS 的 EDD 信息复制到安全的地方
	parse_setup_data();
	//从 boot_params 结构中复制我们在 arch/x86/boot/edd.c 中 BIOS 的 EDD 信息到 edd 结构中
	copy_edd();

	if (!boot_params.hdr.root_flags)
		root_mountflags &= ~MS_RDONLY;
	//初始化init_mm
	setup_initial_init_mm(_text, _etext, _edata, (void *)_brk_end);
	//代码/数据/bss 资源的初始化
	code_resource.start = __pa_symbol(_text);
	code_resource.end = __pa_symbol(_etext)-1;
	rodata_resource.start = __pa_symbol(__start_rodata);
	rodata_resource.end = __pa_symbol(__end_rodata)-1;
	data_resource.start = __pa_symbol(_sdata);
	data_resource.end = __pa_symbol(_edata)-1;
	bss_resource.start = __pa_symbol(__bss_start);
	bss_resource.end = __pa_symbol(__bss_stop)-1;

#ifdef CONFIG_CMDLINE_BOOL
#ifdef CONFIG_CMDLINE_OVERRIDE
	strlcpy(boot_command_line, builtin_cmdline, COMMAND_LINE_SIZE);
#else
	if (builtin_cmdline[0]) {
		/* append boot loader cmdline to builtin */
		strlcat(builtin_cmdline, " ", COMMAND_LINE_SIZE);
		strlcat(builtin_cmdline, boot_command_line, COMMAND_LINE_SIZE);
		strlcpy(boot_command_line, builtin_cmdline, COMMAND_LINE_SIZE);
	}
#endif
#endif

	strlcpy(command_line, boot_command_line, COMMAND_LINE_SIZE);
	*cmdline_p = command_line;

	/*
	 * x86_configure_nx() 会在 parse_early_param() 之前被调用，其目的是检测硬件是否支持 NX（No-eXecute） 特性，
	 * 从而使得早期的 EHCI 调试控制台初始化时，能安全地调用 set_fixmap()。
	 * 后续在解析 early 参数期间，x86_configure_nx() 可能会再次被调用，这次是在 noexec_setup() 中，根据命令行参数中的相关选项进行设置。
	 */
	x86_configure_nx();
	//解析内核命令行并且基于给定的参数创建不同的服务
	parse_early_param();

	if (efi_enabled(EFI_BOOT))
		efi_memblock_x86_reserve_range();

#ifdef CONFIG_MEMORY_HOTPLUG
	/* 内核所使用的内存无法被热拔除，因为 Linux 无法迁移内核页。
	 * 当启用了内存热插拔功能时，我们应当防止 memblock 为内核分配那些可热拔除的内存区域。
	 *
	 * ACPI 的 SRAT 表记录了所有可热插拔的内存区域，但在解析 SRAT 之前，我们并不知道哪些内存是可热拔除的。
	 *
	 * 内核镜像在非常早期就已经加载到内存中，这一步无论如何都无法避免。因此在 NUMA 系统上，我们将内核所在节点（node）标记为不可热拔除。
	 *
	 * 鉴于现代服务器中，一个 NUMA 节点可能拥有十几 GB 的内存，我们可以假设内核镜像周围的内存也是不可热拔除的。
	 * 所以在 SRAT 被解析之前，我们就只在靠近内核镜像的区域分配内存，尽最大可能避免将内核分配到未来可能被热拔除的内存中 */
	if (movable_node_is_enabled())
		memblock_set_bottom_up(true);
#endif

	x86_report_nx();
	//检查内置的 MPS 又称 多重处理器规范 表
	if (acpi_mps_check()) {
#ifdef CONFIG_X86_LOCAL_APIC
		disable_apic = 1;
#endif
		setup_clear_cpu_cap(X86_FEATURE_APIC);
	}

	e820__reserve_setup_data();
	e820__finish_early_params();

	if (efi_enabled(EFI_BOOT))
		efi_init();

	efi_set_secure_boot(boot_params.secure_boot);

#ifdef CONFIG_LOCK_DOWN_IN_SECURE_BOOT
	if (efi_enabled(EFI_SECURE_BOOT))
		security_lock_kernel_down("EFI Secure Boot mode", LOCKDOWN_INTEGRITY_MAX);
#endif

	dmi_setup();//SMBIOS 3.3.0 present.

	/* VMware 检测依赖于 DMI 信息，因此这一步必须在 dmi_setup() 之后执行，并且是在 启动 CPU（boot CPU）上完成的 */
	init_hypervisor_platform();

	tsc_early_init();
	x86_init.resources.probe_roms();

	/* after parse_early_param, so could debug it */
	insert_resource(&iomem_resource, &code_resource);
	insert_resource(&iomem_resource, &rodata_resource);
	insert_resource(&iomem_resource, &data_resource);
	insert_resource(&iomem_resource, &bss_resource);

	e820_add_kernel_range();
	trim_bios_range();
#ifdef CONFIG_X86_32
	if (ppro_with_ram_bug()) {
		e820__range_update(0x70000000ULL, 0x40000ULL, E820_TYPE_RAM,
				  E820_TYPE_RESERVED);
		e820__update_table(e820_table);
		printk(KERN_INFO "fixed physical RAM map:\n");
		e820__print_table("bad_ppro");
	}
#else
	early_gart_iommu_check();
#endif

	/* 部分使用的页面（partially used pages）是不可用的，因此我们需要将大小向上取整（rounding upwards）*/
	max_pfn = e820__end_of_ram_pfn();

	/* 更新 E820 内存表，以标记那些未被 MTRR 设置为 WB（Write-Back）缓存类型的内存区域 */
	mtrr_bp_init();
	if (mtrr_trim_uncached_memory(max_pfn))
		max_pfn = e820__end_of_ram_pfn();

	max_possible_pfn = max_pfn;

	/* 当 CPU 不支持 PAT（Page Attribute Table） 时，必须调用这个函数。如果之前 mtrr_bp_init() 已经通过 
	 * pat_init() 调用了它，那么这次调用将不会产生任何效果 */
	init_cache_modes();

	/* 在 max_pfn 被定义之后、每个内存段的基地址被实际使用之前，为这些内存段定义一个随机的基地址（random base address）*/
	kernel_randomize_memory();

#ifdef CONFIG_X86_32
	/* max_low_pfn get updated here */
	find_low_pfn_range();
#else
	check_x2apic();

	/* How many end-of-memory variables you have, grandma! */
	/* need this before calling reserve_initrd */
	//计算 max_low_pfn ,这是 低端内存 或者低于第一个4GB中的最大页面帧
	if (max_pfn > (1UL<<(32 - PAGE_SHIFT)))
		max_low_pfn = e820__end_of_low_ram_pfn();
	else
		max_low_pfn = max_pfn;
	//通过 __va 宏计算 高端内存 (有更高的内存直接映射上界)中的最大页帧号,并且这个宏会根据给定的物理内存返回一个虚拟地址
	high_memory = (void *)__va(max_pfn * PAGE_SIZE - 1) + 1;
#endif

	/* 查找并保留可能存在的 启动时 SMP（对称多处理器）配置 */
	find_smp_config();
	//在早期阶段分配页表缓冲区。页表缓冲区将被放置在 brk 区段中
	early_alloc_pgt_buf();

	/* 需要在调用 e820__memblock_setup() 之前结束 brk 区域的使用（conclude brk），因为后者可能会调用 memblock_find_in_range, 而这有可能会与 brk 区域发生重叠 */
	//因为我们之前已经创建好了页面缓冲区，所以现在我们使用 reserve_brk 函数为 brk 区段保留内存块
	reserve_brk();

	cleanup_highmap();
	//为 memblock 分配内存设置一个界限，这个界限可以是 ISA_END_ADDRESS 或者 0x100000
	memblock_set_current_limit(ISA_END_ADDRESS);
	//根据e820信息构建memblock内存分配器，开启调试和打印
	e820__memblock_setup();

	/* 需要在 memblock 初始化之后运行，因为它依赖于物理内存大小的信息 */
	sev_setup_arch();

	efi_fake_memmap();
	efi_find_mirror();
	efi_esrt_init();
	efi_mokvar_table_init();

	/* EFI 规范宣称，在调用 ExitBootServices() 之后，启动服务代码（boot service code）将不再被调用。但事实上，这并不是真的 */
	efi_reserve_boot_services();

	/* preallocate 4k for mptable mpc */
	e820__memblock_alloc_reserved_mpc_new();

#ifdef CONFIG_X86_CHECK_BIOS_CORRUPTION
	setup_bios_corruption_check();
#endif

#ifdef CONFIG_X86_32
	printk(KERN_DEBUG "initial memory mapped: [mem 0x00000000-%#010lx]\n",
			(max_pfn_mapped<<PAGE_SHIFT) - 1);
#endif

	/* 为 实模式引导跳板代码（real mode trampoline） 查找可用内存并将其放置到合适的位置。如果在 1MB 以下找不到足够的空闲内存，
	 * 那么在启用了 EFI 的系统上，会在调用 efi_free_boot_services() 时尝试额外回收内存以放置实模式跳板。
	 *
	 * 无条件保留整个前 1MB 的 RAM，因为已知某些 BIOS 会破坏低端内存区域，而这几百 KB 的内存并不值得我们费力去精确检测哪些被破坏了。
	 * Windows 也出于类似原因采取了相同的做法。
	 *
	 * 此外，在使用 SandyBridge 集成显卡 的机器上，或者启用了 crashkernel 的系统中，整个 1MB 区域也无论如何都会被保留 */
	reserve_real_mode();
	// 初始化虚拟地址到物理地址的映射关系, 调用 kernel_physical_mapping_init
	init_mem_mapping();

	idt_setup_early_pf();

	/* 使用当前的 CR4 寄存器值来更新 mmu_cr4_features（以及间接地 trampoline_cr4_features）。
	 * 虽然这可能不是绝对必要的，但要确认这一点就需要审查整个早期引导阶段对 CR4 的所有修改操作。
	 *
	 * 屏蔽掉那些在非 long mode（非长模式）下无效的特性 —— 目前仅限于 PCIDE 
	 * CR4 是 x86 架构的控制寄存器之一，用于启用或禁用处理器的某些特性；
	 * 例如：物理地址扩展（PAE）、页全局启用（PGE）、PCID（进程上下文标识）等 */
	mmu_cr4_features = __read_cr4() & ~X86_CR4_PCIDE;

	memblock_set_current_limit(get_max_mapped());

	/*
	 * NOTE: On x86-32, only from this point on, fixmaps are ready for use.
	 */

#ifdef CONFIG_PROVIDE_OHCI1394_DMA_INIT
	if (init_ohci1394_dma_early)
		init_ohci1394_dma_on_all_controllers();
#endif
	/* Allocate bigger log buffer 设置内核循环缓冲区 */
	setup_log_buf(1);

	efi_set_secure_boot(boot_params.secure_boot);

	reserve_initrd();

	acpi_table_upgrade();
	/* Look for ACPI tables and reserve memory occupied by them. */
	acpi_boot_table_init();

	vsmp_init();

	io_delay_init();

	early_platform_quirks();

	early_acpi_boot_init();
	//内存初始化，包括numa机制初始化
	initmem_init();
	//为直接内存访问（DMA）分配专用区域 参数表示可保留内存的上限地址（将最大页帧号转换为字节地址）
	dma_contiguous_reserve(max_pfn_mapped << PAGE_SHIFT);

	if (boot_cpu_has(X86_FEATURE_GBPAGES))
		hugetlb_cma_reserve(PUD_SHIFT - PAGE_SHIFT);

	/* 在 SRAT 表（System Resource Affinity Table）解析完成之后，再为 crash kernel（崩溃内核）预留内存，以避免它占用 可热插拔的内存区域 */
	// crashkernel=256M
	reserve_crashkernel();

	memblock_find_dma_reserve();

	if (!early_xdbc_setup_hardware())
		early_xdbc_register_console();
	//初始化稀疏内存和内存区域大小
	x86_init.paging.pagetable_init();// native_pagetable_init xen_pagetable_init 

	kasan_init();

	/* 同步内核地址范围（kernel address range）
	 *
	 * FIXME: 后面 setup_cpu_entry_areas() 中的同步操作是否可以替代这里这次的调用？
	 */
	sync_initial_page_table();

	tboot_probe();
	//为 vsyscalls 映射内存空间
	map_vsyscall();

	generic_apic_probe();

	early_quirks();

	/* 从 ACPI 表 中读取 APIC（高级可编程中断控制器） 以及其他一些早期信息 */
	acpi_boot_init();
	x86_dtb_init();

	/* 获取引导时的 SMP（对称多处理器）配置信息 */
	get_smp_config();

	/* 设置本地 APIC 的地址,没有 ACPI 和 MP 表（mptables） 的系统，可能尚未映射本地 APIC（Local APIC），但 prefill_possible_map() 可能会需要访问它 */
	init_apic_mappings();

	prefill_possible_map();

	init_cpu_to_node();
	init_gi_nodes();

	io_apic_init_mappings();

	x86_init.hyper.guest_late_init();

	e820__reserve_resources();
	e820__register_nosave_regions(max_pfn);
	//保留标准 I/O 资源（如 DMA、TIMER、FPU 等）
	x86_init.resources.reserve_resources();// reserve_standard_io_resources

	e820__setup_pci_gap();

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
	if (!efi_enabled(EFI_BOOT) || (efi_mem_type(0xa0000) != EFI_CONVENTIONAL_MEMORY))
		conswitchp = &vga_con;
#endif
#endif
	x86_init.oem.banner();//default_banner

	x86_init.timers.wallclock_init();

	/* 这段代码必须在 setup_local_APIC() 调用之前运行，因为 setup_local_APIC() 会暂时软禁用（soft-disable）本地 APIC（Local APIC），
	   而这会屏蔽（mask）热感中断（thermal LVT interrupt），从而在某些配置了 SMI（系统管理中断）方式的中断传送机制的机器上，导致 软死锁（soft lockups）。
	 */
	therm_lvt_init();
	//初始化机器检查异常
	mcheck_init();
	//注册 jiffies 计时器
	register_refined_jiffies(CLOCK_TICK_RATE);

#ifdef CONFIG_EFI
	if (efi_enabled(EFI_BOOT))
		efi_apply_memmap_quirks();
#endif

	unwind_init();
}

#ifdef CONFIG_X86_32

static struct resource video_ram_resource = {
	.name	= "Video RAM area",
	.start	= 0xa0000,
	.end	= 0xbffff,
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

void __init i386_reserve_resources(void)
{
	request_resource(&iomem_resource, &video_ram_resource);
	reserve_standard_io_resources();
}

#endif /* CONFIG_X86_32 */

static struct notifier_block kernel_offset_notifier = {
	.notifier_call = dump_kernel_offset
};

static int __init register_kernel_offset_dumper(void)
{
	atomic_notifier_chain_register(&panic_notifier_list,
					&kernel_offset_notifier);
	return 0;
}
__initcall(register_kernel_offset_dumper);
