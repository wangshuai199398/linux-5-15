// SPDX-License-Identifier: GPL-2.0
/*
 * Provide common bits of early_ioremap() support for architectures needing
 * temporary mappings during boot before ioremap() is available.
 *
 * This is mostly a direct copy of the x86 early_ioremap implementation.
 *
 * (C) Copyright 1995 1996, 2014 Linus Torvalds
 *
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/fixmap.h>
#include <asm/early_ioremap.h>

#ifdef CONFIG_MMU
static int early_ioremap_debug __initdata;

static int __init early_ioremap_debug_setup(char *str)
{
	early_ioremap_debug = 1;

	return 0;
}
early_param("early_ioremap_debug", early_ioremap_debug_setup);

static int after_paging_init __initdata;

pgprot_t __init __weak early_memremap_pgprot_adjust(resource_size_t phys_addr,
						    unsigned long size,
						    pgprot_t prot)
{
	return prot;
}

void __init early_ioremap_reset(void)
{
	after_paging_init = 1;
}

/*
 * Generally, ioremap() is available after paging_init() has been called.
 * Architectures wanting to allow early_ioremap after paging_init() can
 * define __late_set_fixmap and __late_clear_fixmap to do the right thing.
 */
#ifndef __late_set_fixmap
static inline void __init __late_set_fixmap(enum fixed_addresses idx,
					    phys_addr_t phys, pgprot_t prot)
{
	BUG();
}
#endif

#ifndef __late_clear_fixmap
static inline void __init __late_clear_fixmap(enum fixed_addresses idx)
{
	BUG();
}
#endif
// 包含了初期 ioremap 区域的地址
static void __iomem *prev_map[FIX_BTMAPS_SLOTS] __initdata;
static unsigned long prev_size[FIX_BTMAPS_SLOTS] __initdata;
// 包含了固定映射区域的虚拟地址
static unsigned long slot_virt[FIX_BTMAPS_SLOTS] __initdata;
/*
用初期固定映射的地址填充了 slot_virt 数组。所有初期固定映射地址在内存中都在 __end_of_permanent_fixed_addresses 后面，
它们从 FIX_BITMAP_BEGIN 开始，到 FIX_BITMAP_END 结束。实际上初期 ioremap 会使用 512 个临时引导时映射
填充512个临时的启动时固定映射表来完成无符号长整型矩阵 slot_virt 的初始化
*/
void __init early_ioremap_setup(void)
{
	int i;

	for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
		if (WARN_ON(prev_map[i]))
			break;
    // 用初期固定映射的地址填充了 slot_virt 数组
	for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
		slot_virt[i] = __fix_to_virt(FIX_BTMAP_BEGIN - NR_FIX_BTMAPS*i);
}

static int __init check_early_ioremap_leak(void)
{
	int count = 0;
	int i;

	for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
		if (prev_map[i])
			count++;

	if (WARN(count, KERN_WARNING
		 "Debug warning: early ioremap leak of %d areas detected.\n"
		 "please boot with early_ioremap_debug and report the dmesg.\n",
		 count))
		return 1;
	return 0;
}
late_initcall(check_early_ioremap_leak);

/*
phys_addr - 要映射到虚拟地址上的 I/O 内存区域的基物理地址
size - I/O 内存区域的尺寸；
prot - 页表入口位
*/
static void __init __iomem *
__early_ioremap(resource_size_t phys_addr, unsigned long size, pgprot_t prot)
{
	unsigned long offset;
	resource_size_t last_addr;
	unsigned int nrpages;
	enum fixed_addresses idx;
	int i, slot;

	WARN_ON(system_state >= SYSTEM_RUNNING);

	slot = -1;
	// 首先遍历了所有初期 ioremap 固定映射槽并检查 prev_map 数组中第一个空闲元素，然后将这个值存在了 slot 变量中，另外设置了尺寸
	for (i = 0; i < FIX_BTMAPS_SLOTS; i++) {
		if (!prev_map[i]) {
			slot = i;
			break;
		}
	}

	if (WARN(slot < 0, "%s(%pa, %08lx) not found slot\n",
		 __func__, &phys_addr, size))
		return NULL;

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (WARN_ON(!size || last_addr < phys_addr))
		return NULL;

	prev_size[slot] = size;
	/*
	 * Mappings have to be page-aligned
	 */
	offset = offset_in_page(phys_addr);
	// 使用 PAGE_MASK 用于清空除低 12 位之外的整个 phys_addr
	phys_addr &= PAGE_MASK;
	// 获取这个区域的页对齐尺寸
	size = PAGE_ALIGN(last_addr + 1) - phys_addr;

	/* Mappings have to fit in the FIX_BTMAP area. */
	// 
	nrpages = size >> PAGE_SHIFT;
	if (WARN_ON(nrpages > NR_FIX_BTMAPS))
		return NULL;

	/* Ok, go for it.. */
	// 获取新的 ioremap 区域所占用的页的数量然后计算固定映射下标
	idx = FIX_BTMAP_BEGIN - NR_FIX_BTMAPS*slot;
	//用给定的物理地址填充固定映射区域。循环中的每一次迭代，都调用 __early_set_fixmap 函数，为给定的物理地址加上页的大小 4096，然后更新下标和页的数量
	while (nrpages > 0) {
		if (after_paging_init)
			__late_set_fixmap(idx, phys_addr, prot);
		else
			__early_set_fixmap(idx, phys_addr, prot);
		phys_addr += PAGE_SIZE;
		--idx;
		--nrpages;
	}
	WARN(early_ioremap_debug, "%s(%pa, %08lx) [%d] => %08lx + %08lx\n",
	     __func__, &phys_addr, size, slot, offset, slot_virt[slot]);
	// 因为我们为给定的地址设定了固定映射区域，我们需要将 I/O 重映射的区域的基虚拟地址用 slot 下标保存在 prev_map 数组中,然后返回它。
	prev_map[slot] = (void __iomem *)(offset + slot_virt[slot]);
	return prev_map[slot];
}

/*
两个参数：基地址和 I/O 区域的大小
解除对一个 I/O 内存区域的映射
遍历了固定映射槽并寻找给定地址的槽,这样它就获得了这个固定映射槽的下标，然后通过判断 after_paging_init 的值决定是调用 __late_clear_fixmap 还是 __early_set_fixmap。
当这个值是 0 时会调用 __early_set_fixmap。最终它会将 I/O 内存区域设为 NULL
*/
void __init early_iounmap(void __iomem *addr, unsigned long size)
{
	unsigned long virt_addr;
	unsigned long offset;
	unsigned int nrpages;
	enum fixed_addresses idx;
	int i, slot;

	slot = -1;
	for (i = 0; i < FIX_BTMAPS_SLOTS; i++) {
		if (prev_map[i] == addr) {
			slot = i;
			break;
		}
	}

	if (WARN(slot < 0, "%s(%p, %08lx) not found slot\n",
		  __func__, addr, size))
		return;

	if (WARN(prev_size[slot] != size,
		 "%s(%p, %08lx) [%d] size not consistent %08lx\n",
		  __func__, addr, size, slot, prev_size[slot]))
		return;

	WARN(early_ioremap_debug, "%s(%p, %08lx) [%d]\n",
	      __func__, addr, size, slot);

	virt_addr = (unsigned long)addr;
	if (WARN_ON(virt_addr < fix_to_virt(FIX_BTMAP_BEGIN)))
		return;

	offset = offset_in_page(virt_addr);
	nrpages = PAGE_ALIGN(offset + size) >> PAGE_SHIFT;

	idx = FIX_BTMAP_BEGIN - NR_FIX_BTMAPS*slot;
	while (nrpages > 0) {
		if (after_paging_init)
			__late_clear_fixmap(idx);
		else
			__early_set_fixmap(idx, 0, FIXMAP_PAGE_CLEAR);
		--idx;
		--nrpages;
	}
	prev_map[slot] = NULL;
}

/* Remap an IO device 从 IO 物理地址 映射/解除映射 到虚拟地址 */
void __init __iomem *
early_ioremap(resource_size_t phys_addr, unsigned long size)
{
	return __early_ioremap(phys_addr, size, FIXMAP_PAGE_IO);
}

/* Remap memory */
void __init *
early_memremap(resource_size_t phys_addr, unsigned long size)
{
	pgprot_t prot = early_memremap_pgprot_adjust(phys_addr, size,
						     FIXMAP_PAGE_NORMAL);

	return (__force void *)__early_ioremap(phys_addr, size, prot);
}
#ifdef FIXMAP_PAGE_RO
void __init *
early_memremap_ro(resource_size_t phys_addr, unsigned long size)
{
	pgprot_t prot = early_memremap_pgprot_adjust(phys_addr, size,
						     FIXMAP_PAGE_RO);

	return (__force void *)__early_ioremap(phys_addr, size, prot);
}
#endif

#ifdef CONFIG_ARCH_USE_MEMREMAP_PROT
void __init *
early_memremap_prot(resource_size_t phys_addr, unsigned long size,
		    unsigned long prot_val)
{
	return (__force void *)__early_ioremap(phys_addr, size,
					       __pgprot(prot_val));
}
#endif

#define MAX_MAP_CHUNK	(NR_FIX_BTMAPS << PAGE_SHIFT)

void __init copy_from_early_mem(void *dest, phys_addr_t src, unsigned long size)
{
	unsigned long slop, clen;
	char *p;

	while (size) {
		slop = offset_in_page(src);
		clen = size;
		if (clen > MAX_MAP_CHUNK - slop)
			clen = MAX_MAP_CHUNK - slop;
		p = early_memremap(src & PAGE_MASK, clen + slop);
		memcpy(dest, p + slop, clen);
		early_memunmap(p, clen + slop);
		dest += clen;
		src += clen;
		size -= clen;
	}
}

#else /* CONFIG_MMU */

void __init __iomem *
early_ioremap(resource_size_t phys_addr, unsigned long size)
{
	return (__force void __iomem *)phys_addr;
}

/* Remap memory */
void __init *
early_memremap(resource_size_t phys_addr, unsigned long size)
{
	return (void *)phys_addr;
}
void __init *
early_memremap_ro(resource_size_t phys_addr, unsigned long size)
{
	return (void *)phys_addr;
}

void __init early_iounmap(void __iomem *addr, unsigned long size)
{
}

#endif /* CONFIG_MMU */


void __init early_memunmap(void *addr, unsigned long size)
{
	early_iounmap((__force void __iomem *)addr, size);
}
