// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018-2020 Christoph Hellwig.
 *
 * DMA operations that map physical memory directly without using an IOMMU.
 */
#include <linux/memblock.h> /* for max_pfn */
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/dma-map-ops.h>
#include <linux/scatterlist.h>
#include <linux/pfn.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include "direct.h"

/*
 * Most architectures use ZONE_DMA for the first 16 Megabytes, but some use
 * it for entirely different regions. In that case the arch code needs to
 * override the variable below for dma-direct to work properly.
 */
unsigned int zone_dma_bits __ro_after_init = 24;

static inline dma_addr_t phys_to_dma_direct(struct device *dev,
		phys_addr_t phys)
{
	if (force_dma_unencrypted(dev))
		return phys_to_dma_unencrypted(dev, phys);
	return phys_to_dma(dev, phys);
}

static inline struct page *dma_direct_to_page(struct device *dev,
		dma_addr_t dma_addr)
{
	return pfn_to_page(PHYS_PFN(dma_to_phys(dev, dma_addr)));
}

u64 dma_direct_get_required_mask(struct device *dev)
{
	phys_addr_t phys = (phys_addr_t)(max_pfn - 1) << PAGE_SHIFT;
	u64 max_dma = phys_to_dma_direct(dev, phys);

	return (1ULL << (fls64(max_dma) - 1)) * 2 - 1;
}

static gfp_t dma_direct_optimal_gfp_mask(struct device *dev, u64 dma_mask,
				  u64 *phys_limit)
{
	u64 dma_limit = min_not_zero(dma_mask, dev->bus_dma_limit);

	/*
	 * Optimistically try the zone that the physical address mask falls
	 * into first.  If that returns memory that isn't actually addressable
	 * we will fallback to the next lower zone and try again.
	 *
	 * Note that GFP_DMA32 and GFP_DMA are no ops without the corresponding
	 * zones.
	 */
	*phys_limit = dma_to_phys(dev, dma_limit);
	if (*phys_limit <= DMA_BIT_MASK(zone_dma_bits))
		return GFP_DMA;
	if (*phys_limit <= DMA_BIT_MASK(32))
		return GFP_DMA32;
	return 0;
}

static bool dma_coherent_ok(struct device *dev, phys_addr_t phys, size_t size)
{
	dma_addr_t dma_addr = phys_to_dma_direct(dev, phys);

	if (dma_addr == DMA_MAPPING_ERROR)
		return false;
	return dma_addr + size - 1 <=
		min_not_zero(dev->coherent_dma_mask, dev->bus_dma_limit);
}

static int dma_set_decrypted(struct device *dev, void *vaddr, size_t size)
{
	if (!force_dma_unencrypted(dev))
		return 0;
	return set_memory_decrypted((unsigned long)vaddr, PFN_UP(size));
}

static int dma_set_encrypted(struct device *dev, void *vaddr, size_t size)
{
	int ret;

	if (!force_dma_unencrypted(dev))
		return 0;
	ret = set_memory_encrypted((unsigned long)vaddr, PFN_UP(size));
	if (ret)
		pr_warn_ratelimited("leaking DMA memory that can't be re-encrypted\n");
	return ret;
}

static void __dma_direct_free_pages(struct device *dev, struct page *page,
				    size_t size)
{
	if (IS_ENABLED(CONFIG_DMA_RESTRICTED_POOL) &&
	    swiotlb_free(dev, page, size))
		return;
	dma_free_contiguous(dev, page, size);
}

static struct page *__dma_direct_alloc_pages(struct device *dev, size_t size,
		gfp_t gfp, bool allow_highmem)
{
	int node = dev_to_node(dev);
	struct page *page = NULL;
	u64 phys_limit;

	WARN_ON_ONCE(!PAGE_ALIGNED(size));

	gfp |= dma_direct_optimal_gfp_mask(dev, dev->coherent_dma_mask,
					   &phys_limit);
	if (IS_ENABLED(CONFIG_DMA_RESTRICTED_POOL) &&
	    is_swiotlb_for_alloc(dev)) {
		page = swiotlb_alloc(dev, size);
		if (page && !dma_coherent_ok(dev, page_to_phys(page), size)) {
			__dma_direct_free_pages(dev, page, size);
			return NULL;
		}
		return page;
	}

	page = dma_alloc_contiguous(dev, size, gfp);
	if (page) {
		if (!dma_coherent_ok(dev, page_to_phys(page), size) ||
		    (!allow_highmem && PageHighMem(page))) {
			dma_free_contiguous(dev, page, size);
			page = NULL;
		}
	}
again:
	if (!page)
		page = alloc_pages_node(node, gfp, get_order(size));
	if (page && !dma_coherent_ok(dev, page_to_phys(page), size)) {
		dma_free_contiguous(dev, page, size);
		page = NULL;

		if (IS_ENABLED(CONFIG_ZONE_DMA32) &&
		    phys_limit < DMA_BIT_MASK(64) &&
		    !(gfp & (GFP_DMA32 | GFP_DMA))) {
			gfp |= GFP_DMA32;
			goto again;
		}

		if (IS_ENABLED(CONFIG_ZONE_DMA) && !(gfp & GFP_DMA)) {
			gfp = (gfp & ~GFP_DMA32) | GFP_DMA;
			goto again;
		}
	}

	return page;
}

static void *dma_direct_alloc_from_pool(struct device *dev, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp)
{
	struct page *page;
	u64 phys_mask;
	void *ret;

	gfp |= dma_direct_optimal_gfp_mask(dev, dev->coherent_dma_mask,
					   &phys_mask);
	page = dma_alloc_from_pool(dev, size, &ret, gfp, dma_coherent_ok);
	if (!page)
		return NULL;
	*dma_handle = phys_to_dma_direct(dev, page_to_phys(page));
	return ret;
}

static void *dma_direct_alloc_no_mapping(struct device *dev, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp)
{
	struct page *page;

	page = __dma_direct_alloc_pages(dev, size, gfp & ~__GFP_ZERO, true);
	if (!page)
		return NULL;

	/* remove any dirty cache lines on the kernel alias */
	if (!PageHighMem(page))
		arch_dma_prep_coherent(page, size);

	/* return the page pointer as the opaque cookie */
	*dma_handle = phys_to_dma_direct(dev, page_to_phys(page));
	return page;
}

void *dma_direct_alloc(struct device *dev, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp, unsigned long attrs)
{
	struct page *page;
	void *ret;
	//将请求大小按页对齐
	size = PAGE_ALIGN(size);
	//如果不希望打印分配失败警告，添加 __GFP_NOWARN
	if (attrs & DMA_ATTR_NO_WARN)
		gfp |= __GFP_NOWARN;
	//如果不需要内核映射（比如设备自己控制，不需要内核访问）,走特殊分支,避免 remap，适用于某些高性能或安全场景
	if ((attrs & DMA_ATTR_NO_KERNEL_MAPPING) &&
	    !force_dma_unencrypted(dev) && !is_swiotlb_for_alloc(dev))
		return dma_direct_alloc_no_mapping(dev, size, dma_handle, gfp);
	//如果不能缓存一致（non-coherent）+ 没有 DMA_REMAP，全交给架构特定代码处理
	if (!IS_ENABLED(CONFIG_ARCH_HAS_DMA_SET_UNCACHED) &&
	    !IS_ENABLED(CONFIG_DMA_DIRECT_REMAP) &&
	    !IS_ENABLED(CONFIG_DMA_GLOBAL_POOL) &&
	    !dev_is_dma_coherent(dev) &&
	    !is_swiotlb_for_alloc(dev))
		return arch_dma_alloc(dev, size, dma_handle, gfp, attrs);
	//从全局 coherent 池中分配, 某些非缓存一致设备可从全局共享的 DMA 池分配
	if (IS_ENABLED(CONFIG_DMA_GLOBAL_POOL) &&
	    !dev_is_dma_coherent(dev))
		return dma_alloc_from_global_coherent(dev, size, dma_handle);

	/*
	 * Remapping or decrypting memory may block. If either is required and
	 * we can't block, allocate the memory from the atomic pools.
	 * If restricted DMA (i.e., is_swiotlb_for_alloc) is required, one must
	 * set up another device coherent pool by shared-dma-pool and use
	 * dma_alloc_from_dev_coherent instead.
	 */
	//分配需要解密或 remap，但不能阻塞的情况（如原子上下文）如果当前 GFP 标志不能阻塞，则使用预先分配好的 atomic DMA 池
	if (IS_ENABLED(CONFIG_DMA_COHERENT_POOL) &&
	    !gfpflags_allow_blocking(gfp) &&
	    (force_dma_unencrypted(dev) ||
	     (IS_ENABLED(CONFIG_DMA_DIRECT_REMAP) &&
	      !dev_is_dma_coherent(dev))) &&
	    !is_swiotlb_for_alloc(dev))
		return dma_direct_alloc_from_pool(dev, size, dma_handle, gfp);

	/* we always manually zero the memory once we are done */
	//常规分配页面, 从内核页分配器分配实际页面
	page = __dma_direct_alloc_pages(dev, size, gfp & ~__GFP_ZERO, true);
	if (!page)
		return NULL;
	//如果需要 remap 或 page 是高端内存，做 remap + memset, 这里是标准的 non-coherent remap 逻辑：先准备，再映射，再清零
	if ((IS_ENABLED(CONFIG_DMA_DIRECT_REMAP) &&
	     !dev_is_dma_coherent(dev)) ||
	    (IS_ENABLED(CONFIG_DMA_REMAP) && PageHighMem(page))) {
		/* remove any dirty cache lines on the kernel alias */
		arch_dma_prep_coherent(page, size);

		/* create a coherent mapping */
		ret = dma_common_contiguous_remap(page, size,
				dma_pgprot(dev, PAGE_KERNEL, attrs),
				__builtin_return_address(0));
		if (!ret)
			goto out_free_pages;
		memset(ret, 0, size);
		goto done;
	}
	//如果是高端内存页但不能 remap，则无法访问，直接失败
	if (PageHighMem(page)) {
		/*
		 * Depending on the cma= arguments and per-arch setup
		 * dma_alloc_contiguous could return highmem pages.
		 * Without remapping there is no way to return them here,
		 * so log an error and fail.
		 */
		dev_info(dev, "Rejecting highmem page from CMA.\n");
		goto out_free_pages;
	}
	//获取虚拟地址、清空内容、必要时设置 uncached,最后得到可访问的虚拟地址，确保清零，并根据设备是否 coherent 做缓存设置
	ret = page_address(page);
	if (dma_set_decrypted(dev, ret, size))// 设置 memory decrypted（SEV 相关）
		goto out_free_pages;
	memset(ret, 0, size);

	if (IS_ENABLED(CONFIG_ARCH_HAS_DMA_SET_UNCACHED) &&
	    !dev_is_dma_coherent(dev)) {
		arch_dma_prep_coherent(page, size);
		ret = arch_dma_set_uncached(ret, size);//标记成不可缓存
		if (IS_ERR(ret))
			goto out_encrypt_pages;
	}
done:
	//设置 DMA 地址并返回
	*dma_handle = phys_to_dma_direct(dev, page_to_phys(page));
	return ret;

out_encrypt_pages:
	if (dma_set_encrypted(dev, page_address(page), size))
		return NULL;
out_free_pages:
	__dma_direct_free_pages(dev, page, size);
	return NULL;
}

void dma_direct_free(struct device *dev, size_t size,
		void *cpu_addr, dma_addr_t dma_addr, unsigned long attrs)
{
	unsigned int page_order = get_order(size);

	if ((attrs & DMA_ATTR_NO_KERNEL_MAPPING) &&
	    !force_dma_unencrypted(dev) && !is_swiotlb_for_alloc(dev)) {
		/* cpu_addr is a struct page cookie, not a kernel address */
		dma_free_contiguous(dev, cpu_addr, size);
		return;
	}

	if (!IS_ENABLED(CONFIG_ARCH_HAS_DMA_SET_UNCACHED) &&
	    !IS_ENABLED(CONFIG_DMA_DIRECT_REMAP) &&
	    !IS_ENABLED(CONFIG_DMA_GLOBAL_POOL) &&
	    !dev_is_dma_coherent(dev) &&
	    !is_swiotlb_for_alloc(dev)) {
		arch_dma_free(dev, size, cpu_addr, dma_addr, attrs);
		return;
	}

	if (IS_ENABLED(CONFIG_DMA_GLOBAL_POOL) &&
	    !dev_is_dma_coherent(dev)) {
		if (!dma_release_from_global_coherent(page_order, cpu_addr))
			WARN_ON_ONCE(1);
		return;
	}

	/* If cpu_addr is not from an atomic pool, dma_free_from_pool() fails */
	if (IS_ENABLED(CONFIG_DMA_COHERENT_POOL) &&
	    dma_free_from_pool(dev, cpu_addr, PAGE_ALIGN(size)))
		return;

	if (IS_ENABLED(CONFIG_DMA_REMAP) && is_vmalloc_addr(cpu_addr)) {
		vunmap(cpu_addr);
	} else {
		if (IS_ENABLED(CONFIG_ARCH_HAS_DMA_CLEAR_UNCACHED))
			arch_dma_clear_uncached(cpu_addr, size);
		if (dma_set_encrypted(dev, cpu_addr, size))
			return;
	}

	__dma_direct_free_pages(dev, dma_direct_to_page(dev, dma_addr), size);
}

struct page *dma_direct_alloc_pages(struct device *dev, size_t size,
		dma_addr_t *dma_handle, enum dma_data_direction dir, gfp_t gfp)
{
	struct page *page;
	void *ret;

	if (IS_ENABLED(CONFIG_DMA_COHERENT_POOL) &&
	    force_dma_unencrypted(dev) && !gfpflags_allow_blocking(gfp) &&
	    !is_swiotlb_for_alloc(dev))
		return dma_direct_alloc_from_pool(dev, size, dma_handle, gfp);

	page = __dma_direct_alloc_pages(dev, size, gfp, false);
	if (!page)
		return NULL;

	ret = page_address(page);
	if (dma_set_decrypted(dev, ret, size))
		goto out_free_pages;
	memset(ret, 0, size);
	*dma_handle = phys_to_dma_direct(dev, page_to_phys(page));
	return page;
out_free_pages:
	__dma_direct_free_pages(dev, page, size);
	return NULL;
}

void dma_direct_free_pages(struct device *dev, size_t size,
		struct page *page, dma_addr_t dma_addr,
		enum dma_data_direction dir)
{
	void *vaddr = page_address(page);

	/* If cpu_addr is not from an atomic pool, dma_free_from_pool() fails */
	if (IS_ENABLED(CONFIG_DMA_COHERENT_POOL) &&
	    dma_free_from_pool(dev, vaddr, size))
		return;

	if (dma_set_encrypted(dev, vaddr, size))
		return;
	__dma_direct_free_pages(dev, page, size);
}

#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE) || \
    defined(CONFIG_SWIOTLB)
void dma_direct_sync_sg_for_device(struct device *dev,
		struct scatterlist *sgl, int nents, enum dma_data_direction dir)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nents, i) {
		phys_addr_t paddr = dma_to_phys(dev, sg_dma_address(sg));

		if (unlikely(is_swiotlb_buffer(dev, paddr)))
			swiotlb_sync_single_for_device(dev, paddr, sg->length,
						       dir);

		if (!dev_is_dma_coherent(dev))
			arch_sync_dma_for_device(paddr, sg->length,
					dir);
	}
}
#endif

#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL) || \
    defined(CONFIG_SWIOTLB)
void dma_direct_sync_sg_for_cpu(struct device *dev,
		struct scatterlist *sgl, int nents, enum dma_data_direction dir)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nents, i) {
		phys_addr_t paddr = dma_to_phys(dev, sg_dma_address(sg));

		if (!dev_is_dma_coherent(dev))
			arch_sync_dma_for_cpu(paddr, sg->length, dir);

		if (unlikely(is_swiotlb_buffer(dev, paddr)))
			swiotlb_sync_single_for_cpu(dev, paddr, sg->length,
						    dir);

		if (dir == DMA_FROM_DEVICE)
			arch_dma_mark_clean(paddr, sg->length);
	}

	if (!dev_is_dma_coherent(dev))
		arch_sync_dma_for_cpu_all();
}

void dma_direct_unmap_sg(struct device *dev, struct scatterlist *sgl,
		int nents, enum dma_data_direction dir, unsigned long attrs)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nents, i)
		dma_direct_unmap_page(dev, sg->dma_address, sg_dma_len(sg), dir,
			     attrs);
}
#endif

int dma_direct_map_sg(struct device *dev, struct scatterlist *sgl, int nents,
		enum dma_data_direction dir, unsigned long attrs)
{
	int i;
	struct scatterlist *sg;

	for_each_sg(sgl, sg, nents, i) {
		sg->dma_address = dma_direct_map_page(dev, sg_page(sg),
				sg->offset, sg->length, dir, attrs);
		if (sg->dma_address == DMA_MAPPING_ERROR)
			goto out_unmap;
		sg_dma_len(sg) = sg->length;
	}

	return nents;

out_unmap:
	dma_direct_unmap_sg(dev, sgl, i, dir, attrs | DMA_ATTR_SKIP_CPU_SYNC);
	return -EIO;
}

dma_addr_t dma_direct_map_resource(struct device *dev, phys_addr_t paddr,
		size_t size, enum dma_data_direction dir, unsigned long attrs)
{
	dma_addr_t dma_addr = paddr;

	if (unlikely(!dma_capable(dev, dma_addr, size, false))) {
		dev_err_once(dev,
			     "DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
			     &dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
		WARN_ON_ONCE(1);
		return DMA_MAPPING_ERROR;
	}

	return dma_addr;
}

int dma_direct_get_sgtable(struct device *dev, struct sg_table *sgt,
		void *cpu_addr, dma_addr_t dma_addr, size_t size,
		unsigned long attrs)
{
	struct page *page = dma_direct_to_page(dev, dma_addr);
	int ret;

	ret = sg_alloc_table(sgt, 1, GFP_KERNEL);
	if (!ret)
		sg_set_page(sgt->sgl, page, PAGE_ALIGN(size), 0);
	return ret;
}

bool dma_direct_can_mmap(struct device *dev)
{
	return dev_is_dma_coherent(dev) ||
		IS_ENABLED(CONFIG_DMA_NONCOHERENT_MMAP);
}

int dma_direct_mmap(struct device *dev, struct vm_area_struct *vma,
		void *cpu_addr, dma_addr_t dma_addr, size_t size,
		unsigned long attrs)
{
	unsigned long user_count = vma_pages(vma);
	unsigned long count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	unsigned long pfn = PHYS_PFN(dma_to_phys(dev, dma_addr));
	int ret = -ENXIO;

	vma->vm_page_prot = dma_pgprot(dev, vma->vm_page_prot, attrs);

	if (dma_mmap_from_dev_coherent(dev, vma, cpu_addr, size, &ret))
		return ret;
	if (dma_mmap_from_global_coherent(vma, cpu_addr, size, &ret))
		return ret;

	if (vma->vm_pgoff >= count || user_count > count - vma->vm_pgoff)
		return -ENXIO;
	return remap_pfn_range(vma, vma->vm_start, pfn + vma->vm_pgoff,
			user_count << PAGE_SHIFT, vma->vm_page_prot);
}

int dma_direct_supported(struct device *dev, u64 mask)
{
	u64 min_mask = (max_pfn - 1) << PAGE_SHIFT;

	/*
	 * Because 32-bit DMA masks are so common we expect every architecture
	 * to be able to satisfy them - either by not supporting more physical
	 * memory, or by providing a ZONE_DMA32.  If neither is the case, the
	 * architecture needs to use an IOMMU instead of the direct mapping.
	 */
	if (mask >= DMA_BIT_MASK(32))
		return 1;

	/*
	 * This check needs to be against the actual bit mask value, so use
	 * phys_to_dma_unencrypted() here so that the SME encryption mask isn't
	 * part of the check.
	 */
	if (IS_ENABLED(CONFIG_ZONE_DMA))
		min_mask = min_t(u64, min_mask, DMA_BIT_MASK(zone_dma_bits));
	return mask >= phys_to_dma_unencrypted(dev, min_mask);
}

size_t dma_direct_max_mapping_size(struct device *dev)
{
	/* If SWIOTLB is active, use its maximum mapping size */
	if (is_swiotlb_active(dev) &&
	    (dma_addressing_limited(dev) || is_swiotlb_force_bounce(dev)))
		return swiotlb_max_mapping_size(dev);
	return SIZE_MAX;
}

bool dma_direct_need_sync(struct device *dev, dma_addr_t dma_addr)
{
	return !dev_is_dma_coherent(dev) ||
	       is_swiotlb_buffer(dev, dma_to_phys(dev, dma_addr));
}

/**
 * dma_direct_set_offset - Assign scalar offset for a single DMA range.
 * @dev:	device pointer; needed to "own" the alloced memory.
 * @cpu_start:  beginning of memory region covered by this offset.
 * @dma_start:  beginning of DMA/PCI region covered by this offset.
 * @size:	size of the region.
 *
 * This is for the simple case of a uniform offset which cannot
 * be discovered by "dma-ranges".
 *
 * It returns -ENOMEM if out of memory, -EINVAL if a map
 * already exists, 0 otherwise.
 *
 * Note: any call to this from a driver is a bug.  The mapping needs
 * to be described by the device tree or other firmware interfaces.
 */
int dma_direct_set_offset(struct device *dev, phys_addr_t cpu_start,
			 dma_addr_t dma_start, u64 size)
{
	struct bus_dma_region *map;
	u64 offset = (u64)cpu_start - (u64)dma_start;

	if (dev->dma_range_map) {
		dev_err(dev, "attempt to add DMA range to existing map\n");
		return -EINVAL;
	}

	if (!offset)
		return 0;

	map = kcalloc(2, sizeof(*map), GFP_KERNEL);
	if (!map)
		return -ENOMEM;
	map[0].cpu_start = cpu_start;
	map[0].dma_start = dma_start;
	map[0].offset = offset;
	map[0].size = size;
	dev->dma_range_map = map;
	return 0;
}
