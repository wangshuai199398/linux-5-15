/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MMZONE_H
#define _LINUX_MMZONE_H

#ifndef __ASSEMBLY__
#ifndef __GENERATING_BOUNDS_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <linux/numa.h>
#include <linux/init.h>
#include <linux/seqlock.h>
#include <linux/nodemask.h>
#include <linux/pageblock-flags.h>
#include <linux/page-flags-layout.h>
#include <linux/atomic.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/local_lock.h>
#include <asm/page.h>

/* Free memory management - zoned buddy allocator.  */
#ifndef CONFIG_FORCE_MAX_ZONEORDER
#define MAX_ORDER 11
#else
#define MAX_ORDER CONFIG_FORCE_MAX_ZONEORDER
#endif
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))

/*
 * PAGE_ALLOC_COSTLY_ORDER is the order at which allocations are deemed
 * costly to service.  That is between allocation orders which should
 * coalesce naturally under reasonable reclaim pressure and those which
 * will not.
 */
#define PAGE_ALLOC_COSTLY_ORDER 3

enum migratetype {
	MIGRATE_UNMOVABLE,
	MIGRATE_MOVABLE,
	MIGRATE_RECLAIMABLE,
	MIGRATE_PCPTYPES,	/* the number of types on the pcp lists */
	MIGRATE_HIGHATOMIC = MIGRATE_PCPTYPES,
#ifdef CONFIG_CMA
	/*
	 * MIGRATE_CMA migration type is designed to mimic the way
	 * ZONE_MOVABLE works.  Only movable pages can be allocated
	 * from MIGRATE_CMA pageblocks and page allocator never
	 * implicitly change migration type of MIGRATE_CMA pageblock.
	 *
	 * The way to use it is to change migratetype of a range of
	 * pageblocks to MIGRATE_CMA which can be done by
	 * __free_pageblock_cma() function.  What is important though
	 * is that a range of pageblocks must be aligned to
	 * MAX_ORDER_NR_PAGES should biggest page be bigger than
	 * a single pageblock.
	 */
	MIGRATE_CMA,
#endif
#ifdef CONFIG_MEMORY_ISOLATION
	MIGRATE_ISOLATE,	/* can't allocate from here */
#endif
	MIGRATE_TYPES
};

/* In mm/page_alloc.c; keep in sync also with show_migration_types() there */
extern const char * const migratetype_names[MIGRATE_TYPES];

#ifdef CONFIG_CMA
#  define is_migrate_cma(migratetype) unlikely((migratetype) == MIGRATE_CMA)
#  define is_migrate_cma_page(_page) (get_pageblock_migratetype(_page) == MIGRATE_CMA)
#else
#  define is_migrate_cma(migratetype) false
#  define is_migrate_cma_page(_page) false
#endif

static inline bool is_migrate_movable(int mt)
{
	return is_migrate_cma(mt) || mt == MIGRATE_MOVABLE;
}

#define for_each_migratetype_order(order, type) \
	for (order = 0; order < MAX_ORDER; order++) \
		for (type = 0; type < MIGRATE_TYPES; type++)

extern int page_group_by_mobility_disabled;

#define MIGRATETYPE_MASK ((1UL << PB_migratetype_bits) - 1)

#define get_pageblock_migratetype(page)					\
	get_pfnblock_flags_mask(page, page_to_pfn(page), MIGRATETYPE_MASK)

struct free_area {
	struct list_head	free_list[MIGRATE_TYPES];
	unsigned long		nr_free;
};

static inline struct page *get_page_from_free_area(struct free_area *area,
					    int migratetype)
{
	return list_first_entry_or_null(&area->free_list[migratetype],
					struct page, lru);
}

static inline bool free_area_empty(struct free_area *area, int migratetype)
{
	return list_empty(&area->free_list[migratetype]);
}

struct pglist_data;

/*
 * Add a wild amount of padding here to ensure data fall into separate
 * cachelines.  There are very few zone structures in the machine, so space
 * consumption is not a concern here.
 */
#if defined(CONFIG_SMP)
struct zone_padding {
	char x[0];
} ____cacheline_internodealigned_in_smp;
#define ZONE_PADDING(name)	struct zone_padding name;
#else
#define ZONE_PADDING(name)
#endif

#ifdef CONFIG_NUMA
enum numa_stat_item {
	NUMA_HIT,		/* allocated in intended node */
	NUMA_MISS,		/* allocated in non intended node */
	NUMA_FOREIGN,		/* was intended here, hit elsewhere */
	NUMA_INTERLEAVE_HIT,	/* interleaver preferred this zone */
	NUMA_LOCAL,		/* allocation from local node */
	NUMA_OTHER,		/* allocation from other node */
	NR_VM_NUMA_EVENT_ITEMS
};
#else
#define NR_VM_NUMA_EVENT_ITEMS 0
#endif

enum zone_stat_item {
	/* First 128 byte cacheline (assuming 64 bit words) */
	NR_FREE_PAGES,
	NR_ZONE_LRU_BASE, /* Used only for compaction and reclaim retry */
	NR_ZONE_INACTIVE_ANON = NR_ZONE_LRU_BASE,
	NR_ZONE_ACTIVE_ANON,
	NR_ZONE_INACTIVE_FILE,
	NR_ZONE_ACTIVE_FILE,
	NR_ZONE_UNEVICTABLE,
	NR_ZONE_WRITE_PENDING,	/* Count of dirty, writeback and unstable pages */
	NR_MLOCK,		/* mlock()ed pages found and moved off LRU */
	/* Second 128 byte cacheline */
	NR_BOUNCE,
#if IS_ENABLED(CONFIG_ZSMALLOC)
	NR_ZSPAGES,		/* allocated in zsmalloc */
#endif
	NR_FREE_CMA_PAGES,
	NR_VM_ZONE_STAT_ITEMS };

enum node_stat_item {
	NR_LRU_BASE,
	NR_INACTIVE_ANON = NR_LRU_BASE, /* must match order of LRU_[IN]ACTIVE */
	NR_ACTIVE_ANON,		/*  "     "     "   "       "         */
	NR_INACTIVE_FILE,	/*  "     "     "   "       "         */
	NR_ACTIVE_FILE,		/*  "     "     "   "       "         */
	NR_UNEVICTABLE,		/*  "     "     "   "       "         */
	NR_SLAB_RECLAIMABLE_B,
	NR_SLAB_UNRECLAIMABLE_B,
	NR_ISOLATED_ANON,	/* Temporary isolated pages from anon lru */
	NR_ISOLATED_FILE,	/* Temporary isolated pages from file lru */
	WORKINGSET_NODES,
	WORKINGSET_REFAULT_BASE,
	WORKINGSET_REFAULT_ANON = WORKINGSET_REFAULT_BASE,
	WORKINGSET_REFAULT_FILE,
	WORKINGSET_ACTIVATE_BASE,
	WORKINGSET_ACTIVATE_ANON = WORKINGSET_ACTIVATE_BASE,
	WORKINGSET_ACTIVATE_FILE,
	WORKINGSET_RESTORE_BASE,
	WORKINGSET_RESTORE_ANON = WORKINGSET_RESTORE_BASE,
	WORKINGSET_RESTORE_FILE,
	WORKINGSET_NODERECLAIM,
	NR_ANON_MAPPED,	/* Mapped anonymous pages */
	NR_FILE_MAPPED,	/* pagecache pages mapped into pagetables.
			   only modified from process context */
	NR_FILE_PAGES,
	NR_FILE_DIRTY,
	NR_WRITEBACK,
	NR_WRITEBACK_TEMP,	/* Writeback using temporary buffers */
	NR_SHMEM,		/* shmem pages (included tmpfs/GEM pages) */
	NR_SHMEM_THPS,
	NR_SHMEM_PMDMAPPED,
	NR_FILE_THPS,
	NR_FILE_PMDMAPPED,
	NR_ANON_THPS,
	NR_VMSCAN_WRITE,
	NR_VMSCAN_IMMEDIATE,	/* Prioritise for reclaim when writeback ends */
	NR_DIRTIED,		/* page dirtyings since bootup */
	NR_WRITTEN,		/* page writings since bootup */
	NR_KERNEL_MISC_RECLAIMABLE,	/* reclaimable non-slab kernel pages */
	NR_FOLL_PIN_ACQUIRED,	/* via: pin_user_page(), gup flag: FOLL_PIN */
	NR_FOLL_PIN_RELEASED,	/* pages returned via unpin_user_page() */
	NR_KERNEL_STACK_KB,	/* measured in KiB */
#if IS_ENABLED(CONFIG_SHADOW_CALL_STACK)
	NR_KERNEL_SCS_KB,	/* measured in KiB */
#endif
	NR_PAGETABLE,		/* used for pagetables */
#ifdef CONFIG_SWAP
	NR_SWAPCACHE,
#endif
	NR_VM_NODE_STAT_ITEMS
};

/*
 * Returns true if the item should be printed in THPs (/proc/vmstat
 * currently prints number of anon, file and shmem THPs. But the item
 * is charged in pages).
 */
static __always_inline bool vmstat_item_print_in_thp(enum node_stat_item item)
{
	if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE))
		return false;

	return item == NR_ANON_THPS ||
	       item == NR_FILE_THPS ||
	       item == NR_SHMEM_THPS ||
	       item == NR_SHMEM_PMDMAPPED ||
	       item == NR_FILE_PMDMAPPED;
}

/*
 * Returns true if the value is measured in bytes (most vmstat values are
 * measured in pages). This defines the API part, the internal representation
 * might be different.
 */
static __always_inline bool vmstat_item_in_bytes(int idx)
{
	/*
	 * Global and per-node slab counters track slab pages.
	 * It's expected that changes are multiples of PAGE_SIZE.
	 * Internally values are stored in pages.
	 *
	 * Per-memcg and per-lruvec counters track memory, consumed
	 * by individual slab objects. These counters are actually
	 * byte-precise.
	 */
	return (idx == NR_SLAB_RECLAIMABLE_B ||
		idx == NR_SLAB_UNRECLAIMABLE_B);
}

/*
 * We do arithmetic on the LRU lists in various places in the code,
 * so it is important to keep the active lists LRU_ACTIVE higher in
 * the array than the corresponding inactive lists, and to keep
 * the *_FILE lists LRU_FILE higher than the corresponding _ANON lists.
 *
 * This has to be kept in sync with the statistics in zone_stat_item
 * above and the descriptions in vmstat_text in mm/vmstat.c
 */
#define LRU_BASE 0
#define LRU_ACTIVE 1
#define LRU_FILE 2

/* 内存页总共分两类，一类是匿名页，和虚拟地址空间进行关联；一类是内存映射，不但和虚拟地址空间关联，还和文件管理关联
   每一类都有两个列表，一个是 active，一个是 inactive。顾名思义，active 就是比较活跃的，inactive 就是不怎么活跃的。
   这两个里面的页会变化，过一段时间，活跃的可能变为不活跃，不活跃的可能变为活跃。如果要换出内存，那就是从不活跃的列表中找出最不活跃的，换出到硬盘上
*/
enum lru_list {
	LRU_INACTIVE_ANON = LRU_BASE,
	LRU_ACTIVE_ANON = LRU_BASE + LRU_ACTIVE,
	LRU_INACTIVE_FILE = LRU_BASE + LRU_FILE,
	LRU_ACTIVE_FILE = LRU_BASE + LRU_FILE + LRU_ACTIVE,
	LRU_UNEVICTABLE,
	NR_LRU_LISTS
};

#define for_each_lru(lru) for (lru = 0; lru < NR_LRU_LISTS; lru++)

#define for_each_evictable_lru(lru) for (lru = 0; lru <= LRU_ACTIVE_FILE; lru++)

static inline bool is_file_lru(enum lru_list lru)
{
	return (lru == LRU_INACTIVE_FILE || lru == LRU_ACTIVE_FILE);
}

static inline bool is_active_lru(enum lru_list lru)
{
	return (lru == LRU_ACTIVE_ANON || lru == LRU_ACTIVE_FILE);
}

#define ANON_AND_FILE 2

enum lruvec_flags {
	LRUVEC_CONGESTED,		/* lruvec has many dirty pages
					 * backed by a congested BDI
					 */
};

struct lruvec {
	struct list_head		lists[NR_LRU_LISTS];
	/* per lruvec lru_lock for memcg */
	spinlock_t			lru_lock;
	/*
	 * These track the cost of reclaiming one LRU - file or anon -
	 * over the other. As the observed cost of reclaiming one LRU
	 * increases, the reclaim scan balance tips toward the other.
	 */
	unsigned long			anon_cost;
	unsigned long			file_cost;
	/* Non-resident age, driven by LRU movement */
	atomic_long_t			nonresident_age;
	/* Refaults at the time of last reclaim cycle */
	unsigned long			refaults[ANON_AND_FILE];
	/* Various lruvec state flags (enum lruvec_flags) */
	unsigned long			flags;
#ifdef CONFIG_MEMCG
	struct pglist_data *pgdat;
#endif
};

/* Isolate unmapped pages */
#define ISOLATE_UNMAPPED	((__force isolate_mode_t)0x2)
/* Isolate for asynchronous migration */
#define ISOLATE_ASYNC_MIGRATE	((__force isolate_mode_t)0x4)
/* Isolate unevictable pages */
#define ISOLATE_UNEVICTABLE	((__force isolate_mode_t)0x8)

/* LRU Isolation modes. */
typedef unsigned __bitwise isolate_mode_t;

enum zone_watermarks {
	WMARK_MIN,
	WMARK_LOW,
	WMARK_HIGH,
	NR_WMARK
};

/*
 * One per migratetype for each PAGE_ALLOC_COSTLY_ORDER plus one additional
 * for pageblock size for THP if configured.
 */
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
#define NR_PCP_THP 1
#else
#define NR_PCP_THP 0
#endif
#define NR_PCP_LISTS (MIGRATE_PCPTYPES * (PAGE_ALLOC_COSTLY_ORDER + 1 + NR_PCP_THP))

/*
 * Shift to encode migratetype and order in the same integer, with order
 * in the least significant bits.
 */
#define NR_PCP_ORDER_WIDTH 8
#define NR_PCP_ORDER_MASK ((1<<NR_PCP_ORDER_WIDTH) - 1)

#define min_wmark_pages(z) (z->_watermark[WMARK_MIN] + z->watermark_boost)
#define low_wmark_pages(z) (z->_watermark[WMARK_LOW] + z->watermark_boost)
#define high_wmark_pages(z) (z->_watermark[WMARK_HIGH] + z->watermark_boost)
#define wmark_pages(z, i) (z->_watermark[i] + z->watermark_boost)

/* Fields and list protected by pagesets local_lock in page_alloc.c */
struct per_cpu_pages {
	int count;		/* number of pages in the list */
	int high;		/* high watermark, emptying needed */
	int batch;		/* chunk size for buddy add/remove */
	short free_factor;	/* batch scaling factor during free */
#ifdef CONFIG_NUMA
	short expire;		/* When 0, remote pagesets are drained */
#endif

	/* Lists of pages, one per migrate type stored on the pcp-lists */
	struct list_head lists[NR_PCP_LISTS];
};

struct per_cpu_zonestat {
#ifdef CONFIG_SMP
	s8 vm_stat_diff[NR_VM_ZONE_STAT_ITEMS];
	s8 stat_threshold;
#endif
#ifdef CONFIG_NUMA
	/*
	 * Low priority inaccurate counters that are only folded
	 * on demand. Use a large type to avoid the overhead of
	 * folding during refresh_cpu_vm_stats.
	 */
	unsigned long vm_numa_event[NR_VM_NUMA_EVENT_ITEMS];
#endif
};

struct per_cpu_nodestat {
	s8 stat_threshold;
	s8 vm_node_stat_diff[NR_VM_NODE_STAT_ITEMS];
};

#endif /* !__GENERATING_BOUNDS.H */

enum zone_type {
	/*
	 * ZONE_DMA 和 ZONE_DMA32 用于在某些外设无法对整个可寻址内存（即 ZONE_NORMAL）进行 DMA（直接内存访问）时的情况。
	 * 在某些架构中，如果 DMA 区域覆盖了整个 32 位地址空间，就会使用 ZONE_DMA32。而 ZONE_DMA 则保留给那些 DMA 地址限制更小的设备使用。
	 * 这种区分很重要，因为一旦定义了 ZONE_DMA32，就默认假设外设使用的是 32 位的 DMA 掩码（DMA mask）。
	 * 一些 64 位平台可能同时需要 ZONE_DMA 和 ZONE_DMA32，因为它们支持具有不同 DMA 地址限制的外设。
	 */
#ifdef CONFIG_ZONE_DMA
	//ZONE_DMA 地址段最低的一块内存区域, 支持DMA
	ZONE_DMA,
#endif
#ifdef CONFIG_ZONE_DMA32
	//支持32位地址总线的DMA设备, 只有在64位系统里才有效
	ZONE_DMA32,
#endif
	/*普通的可寻址内存位于 ZONE_NORMAL 区域。如果 DMA 设备支持对所有可寻址内存进行传输操作，那么 DMA 操作是可以在 ZONE_NORMAL 区域的页面上执行的*/
	//直接映射区，从物理内存到虚拟内存的内核区域，通过加上一个常量直接映射
	ZONE_NORMAL,
#ifdef CONFIG_HIGHMEM
	/*
	 * 高端内存区，就是上一节讲的，对于 32 位系统来说超过 896M 的地方，对于 64 位没必要有的一段区域
	 */
	ZONE_HIGHMEM,
#endif
	/*
	 * ZONE_MOVABLE 与 ZONE_NORMAL 类似，但它只包含可移动的页面，除了以下列出的少数特殊情况
	 * 这个区域的主要用途包括：
	 * 提高内存下线（memory offlining）或内存热拔插的成功率；
	 * 将不可移动的内存分配局部限制在其他 zone 中，例如为了增加可用的大页（THP/huge pages）数量
	 *
	 * 一些重要的特殊情况包括：
	 * 1. 固定页（Pinned pages）：
	 *    对可移动页进行长期 pin 操作，会使其变得不可移动。因此，不允许在 ZONE_MOVABLE 中长期 pin 页面。页面在被 fault 并固定时，会直接从合适的 
	 *    zone 分配；如果在 pin 操作前，地址空间中已有页面来自 ZONE_MOVABLE，就会尝试将这些页面迁移到其他 zone。若迁移失败，则 pin 操作失败。
	 * 2. memblock 分配造成的不可移动页面：
	 *    内核参数 kernelcore 和 movablecore 可能会在引导后导致 ZONE_MOVABLE 中出现不可移动页面，进而导致内存下线或页面分配提前失败。
	 * 3. 内存空洞（memory holes）：
	 *    某些稀有情况下，比如 zone 所跨越的 section 只部分填充，也可能导致 ZONE_MOVABLE 中出现“空洞”。这也会影响后续的下线或分配操作。
	 * 4. 被硬件毒化的页（PG_hwpoison）：
	 *    虽然在内存下线时可以跳过这些页面，但它们无法被重新分配。
	 * 5. 不可移动的 PG_offline 页：
	 *    在半虚拟化环境下（如 XEN-balloon、Hyper-V balloon、virtio-mem），热插拔内存可能部分由伙伴系统管理，未被管理的部分是不可移动的 PG_offline 页面。
	 *    某些机制如 virtio-mem 可以通过 alloc_contig_range() 把这些页重新“隐藏”掉，以实现类似“内存拔出”的效果，但它们仍然不可移动或不可分配。
	 * 6. ZERO_PAGE(0)：
	 *    某些平台中，ZERO_PAGE(0) 的分配方式不同，可能最终落入 ZONE_MOVABLE，但这类页是不能迁移的。
	 * 7. 内存热插拔与 vmemmap 页：
	 *    使用 memmap_on_memory 时，如果把内存上线到 ZONE_MOVABLE，描述这部分内存的 vmemmap 页面也会落入此区。虽然这些页面是“自我存储”的
	 *   （自我描述其所在范围），它们理论上不可移动，但在实际下线中会被视作可移动页。
	 *
	 * 总结：
	 * 在 ZONE_MOVABLE 中，一般不应包含任何真正不可移动的分配，否则会削弱内存热插拔和大页分配的能力。但是由于上述种种特殊情况，即便系统认为页面是可移动的
	 * （如通过 has_unmovable_pages() 判断），仍可能存在假阳性，即实际迁移会失败。因此，像 alloc_contig_range() 这样的内存分配器必须预期迁移操作可能失败
	 */
	//可移动区域，通过将物理内存划分为可移动分配区域和不可移动分配区域来避免内存碎片
	ZONE_MOVABLE,
#ifdef CONFIG_ZONE_DEVICE
	ZONE_DEVICE,
#endif
	__MAX_NR_ZONES

};

#ifndef __GENERATING_BOUNDS_H

#define ASYNC_AND_SYNC 2

struct zone {
	/* Read-mostly fields */

	/* zone watermarks, access with *_wmark_pages(zone) macros */
	unsigned long _watermark[NR_WMARK];
	unsigned long watermark_boost;

	unsigned long nr_reserved_highatomic;

	/*
	 * We don't know if the memory that we're going to allocate will be
	 * freeable or/and it will be released eventually, so to avoid totally
	 * wasting several GB of ram we must reserve some of the lower zone
	 * memory (otherwise we risk to run OOM on the lower zones despite
	 * there being tons of freeable ram on the higher zones).  This array is
	 * recalculated at runtime if the sysctl_lowmem_reserve_ratio sysctl
	 * changes.
	 */
	long lowmem_reserve[MAX_NR_ZONES];

#ifdef CONFIG_NUMA
	int node;
#endif
	struct pglist_data	*zone_pgdat;
	//区分冷热页,每个 CPU 一个,如果一个页被加载到 CPU 高速缓存里面，这就是一个热页（Hot Page），CPU 读起来速度会快很多，如果没有就是冷页（Cold Page）
	struct per_cpu_pages	__percpu *per_cpu_pageset;
	struct per_cpu_zonestat	__percpu *per_cpu_zonestats;
	/*
	 * the high and batch values are copied to individual pagesets for
	 * faster access
	 */
	int pageset_high;
	int pageset_batch;

#ifndef CONFIG_SPARSEMEM
	/*
	 * Flags for a pageblock_nr_pages block. See pageblock-flags.h.
	 * In SPARSEMEM, this map is stored in struct mem_section
	 */
	unsigned long		*pageblock_flags;
#endif /* CONFIG_SPARSEMEM */

	/* zone_start_pfn == zone_start_paddr >> PAGE_SHIFT */
	//属于这个 zone 的第一个页
	unsigned long		zone_start_pfn;

	/*
	 * spanned_pages is the total pages spanned by the zone, including
	 * holes, which is calculated as:
	 * 	spanned_pages = zone_end_pfn - zone_start_pfn;
	 *
	 * present_pages is physical pages existing within the zone, which
	 * is calculated as:
	 *	present_pages = spanned_pages - absent_pages(pages in holes);
	 *
	 * present_early_pages is present pages existing within the zone
	 * located on memory available since early boot, excluding hotplugged
	 * memory.
	 *
	 * managed_pages is present pages managed by the buddy system, which
	 * is calculated as (reserved_pages includes pages allocated by the
	 * bootmem allocator):
	 *	managed_pages = present_pages - reserved_pages;
	 *
	 * cma pages is present pages that are assigned for CMA use
	 * (MIGRATE_CMA).
	 *
	 * So present_pages may be used by memory hotplug or memory power
	 * management logic to figure out unmanaged pages by checking
	 * (present_pages - managed_pages). And managed_pages should be used
	 * by page allocator and vm scanner to calculate all kinds of watermarks
	 * and thresholds.
	 *
	 * Locking rules:
	 *
	 * zone_start_pfn and spanned_pages are protected by span_seqlock.
	 * It is a seqlock because it has to be read outside of zone->lock,
	 * and it is done in the main allocator path.  But, it is written
	 * quite infrequently.
	 *
	 * The span_seq lock is declared along with zone->lock because it is
	 * frequently read in proximity to zone->lock.  It's good to
	 * give them a chance of being in the same cacheline.
	 *
	 * Write access to present_pages at runtime should be protected by
	 * mem_hotplug_begin/end(). Any reader who can't tolerant drift of
	 * present_pages should get_online_mems() to get a stable value.
	 */
	//这个 zone 被伙伴系统管理的所有的 page 数目
	atomic_long_t		managed_pages;
	//不管中间有没有物理内存空洞，反正就是最后的页号减去起始的页号
	unsigned long		spanned_pages;
	//这个 zone 在物理内存中真实存在的所有 page 数目
	unsigned long		present_pages;
#if defined(CONFIG_MEMORY_HOTPLUG)
	unsigned long		present_early_pages;
#endif
#ifdef CONFIG_CMA
	unsigned long		cma_pages;
#endif
	// zone 的名称
	const char		*name;

#ifdef CONFIG_MEMORY_ISOLATION
	/*
	 * Number of isolated pageblock. It is used to solve incorrect
	 * freepage counting problem due to racy retrieving migratetype
	 * of pageblock. Protected by zone->lock.
	 */
	unsigned long		nr_isolate_pageblock;
#endif

#ifdef CONFIG_MEMORY_HOTPLUG
	/* see spanned/present_pages for more description */
	seqlock_t		span_seqlock;
#endif

	int initialized;

	/* Write-intensive fields used from the page allocator */
	ZONE_PADDING(_pad1_)

	/* 管理了zone下面所有页面的伙伴系统 每个元素代表空闲可分配连续4K、8K、16K、4M(2^i个连续页的空闲块)的内存链表*/
	struct free_area	free_area[MAX_ORDER];

	/* zone flags, see below */
	unsigned long		flags;

	/* Primarily protects free_area */
	spinlock_t		lock;

	/* Write-intensive fields used by compaction and vmstats. */
	ZONE_PADDING(_pad2_)

	/*
	 * When free pages are below this point, additional steps are taken
	 * when reading the number of free pages to avoid per-cpu counter
	 * drift allowing watermarks to be breached
	 */
	unsigned long percpu_drift_mark;

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	/* pfn where compaction free scanner should start */
	unsigned long		compact_cached_free_pfn;
	/* pfn where compaction migration scanner should start */
	unsigned long		compact_cached_migrate_pfn[ASYNC_AND_SYNC];
	unsigned long		compact_init_migrate_pfn;
	unsigned long		compact_init_free_pfn;
#endif

#ifdef CONFIG_COMPACTION
	/*
	 * On compaction failure, 1<<compact_defer_shift compactions
	 * are skipped before trying again. The number attempted since
	 * last failure is tracked with compact_considered.
	 * compact_order_failed is the minimum compaction failed order.
	 */
	unsigned int		compact_considered;
	unsigned int		compact_defer_shift;
	int			compact_order_failed;
#endif

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	/* Set to true when the PG_migrate_skip bits should be cleared */
	bool			compact_blockskip_flush;
#endif

	bool			contiguous;

	ZONE_PADDING(_pad3_)
	/* Zone statistics */
	atomic_long_t		vm_stat[NR_VM_ZONE_STAT_ITEMS];
	atomic_long_t		vm_numa_event[NR_VM_NUMA_EVENT_ITEMS];
} ____cacheline_internodealigned_in_smp;

enum pgdat_flags {
	PGDAT_DIRTY,			/* reclaim scanning has recently found
					 * many dirty file pages at the tail
					 * of the LRU.
					 */
	PGDAT_WRITEBACK,		/* reclaim scanning has recently found
					 * many pages under writeback
					 */
	PGDAT_RECLAIM_LOCKED,		/* prevents concurrent reclaim */
};

enum zone_flags {
	ZONE_BOOSTED_WATERMARK,		/* zone recently boosted watermarks.
					 * Cleared when kswapd is woken.
					 */
	ZONE_RECLAIM_ACTIVE,		/* kswapd may be scanning the zone. */
};

static inline unsigned long zone_managed_pages(struct zone *zone)
{
	return (unsigned long)atomic_long_read(&zone->managed_pages);
}

static inline unsigned long zone_cma_pages(struct zone *zone)
{
#ifdef CONFIG_CMA
	return zone->cma_pages;
#else
	return 0;
#endif
}

static inline unsigned long zone_end_pfn(const struct zone *zone)
{
	return zone->zone_start_pfn + zone->spanned_pages;
}

static inline bool zone_spans_pfn(const struct zone *zone, unsigned long pfn)
{
	return zone->zone_start_pfn <= pfn && pfn < zone_end_pfn(zone);
}

static inline bool zone_is_initialized(struct zone *zone)
{
	return zone->initialized;
}

static inline bool zone_is_empty(struct zone *zone)
{
	return zone->spanned_pages == 0;
}

/*
 * Return true if [start_pfn, start_pfn + nr_pages) range has a non-empty
 * intersection with the given zone
 */
static inline bool zone_intersects(struct zone *zone,
		unsigned long start_pfn, unsigned long nr_pages)
{
	if (zone_is_empty(zone))
		return false;
	if (start_pfn >= zone_end_pfn(zone) ||
	    start_pfn + nr_pages <= zone->zone_start_pfn)
		return false;

	return true;
}

/*
 * The "priority" of VM scanning is how much of the queues we will scan in one
 * go. A value of 12 for DEF_PRIORITY implies that we will scan 1/4096th of the
 * queues ("queue_length >> 12") during an aging round.
 */
#define DEF_PRIORITY 12

/* Maximum number of zones on a zonelist */
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)

enum {
	ZONELIST_FALLBACK,	/* zonelist with fallback */
#ifdef CONFIG_NUMA
	/*
	 * The NUMA zonelists are doubled because we need zonelists that
	 * restrict the allocations to a single node for __GFP_THISNODE.
	 */
	ZONELIST_NOFALLBACK,	/* zonelist without fallback (__GFP_THISNODE) */
#endif
	MAX_ZONELISTS
};

/*
 * This struct contains information about a zone in a zonelist. It is stored
 * here to avoid dereferences into large structures and lookups of tables
 */
struct zoneref {
	struct zone *zone;	/* Pointer to actual zone */
	int zone_idx;		/* zone_idx(zoneref->zone) */
};

/*
 * One allocation request operates on a zonelist. A zonelist
 * is a list of zones, the first one is the 'goal' of the
 * allocation, the other zones are fallback zones, in decreasing
 * priority.
 *
 * To speed the reading of the zonelist, the zonerefs contain the zone index
 * of the entry being read. Helper functions to access information given
 * a struct zoneref are
 *
 * zonelist_zone()	- Return the struct zone * for an entry in _zonerefs
 * zonelist_zone_idx()	- Return the index of the zone for an entry
 * zonelist_node_idx()	- Return the index of the node for an entry
 */
struct zonelist {
	struct zoneref _zonerefs[MAX_ZONES_PER_ZONELIST + 1];
};

/*
 * The array of struct pages for flatmem.
 * It must be declared for SPARSEMEM as well because there are configurations
 * that rely on that.
 */
extern struct page *mem_map;

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
struct deferred_split {
	spinlock_t split_queue_lock;
	struct list_head split_queue;
	unsigned long split_queue_len;
};
#endif

/*
 * 在 NUMA（非统一内存访问）架构的机器上，每个 NUMA 节点都会有一个 pg_data_t 结构，用于描述该节点的内存布局。
 * 而在 UMA（统一内存访问）架构的机器上，则只会有一个 pglist_data 结构，用来描述整个系统的内存
 * 
 * 内存统计信息以及页面置换（page replacement）所需的数据结构是以“zone”为单位来维护的
 * node 内存通过 pglist_data 来呈现
 */
typedef struct pglist_data {
	/* node_zones 只包含当前节点（THIS node）上的所有 zone。
	 * 并不是所有的 zone 都一定被填充（populated），但这个列表是完整的。
	 * 它不仅被当前节点的 node_zonelists 引用，也可能被其他节点的 node_zonelists 引用 */
	//每一个节点分成一个个区域 zone，放在数组 node_zones 里面。这个数组的大小为 __MAX_NR_ZONES
	struct zone node_zones[MAX_NR_ZONES];

	/* node_zonelists 包含对所有节点中所有 zone 的引用。通常，列表中的前几个 zone 引用的是当前节点（本节点）的 node_zones */
	//备用节点和它的内存区域的情况
	struct zonelist node_zonelists[MAX_ZONELISTS];
	//当前节点的区域的数量
	int nr_zones; /* number of populated zones in this node */
#ifdef CONFIG_FLATMEM	/* means !SPARSEMEM */
	struct page *node_mem_map;
#ifdef CONFIG_PAGE_EXTENSION
	struct page_ext *node_page_ext;
#endif
#endif
#if defined(CONFIG_MEMORY_HOTPLUG) || defined(CONFIG_DEFERRED_STRUCT_PAGE_INIT)
	/*
	 * Must be held any time you expect node_start_pfn,
	 * node_present_pages, node_spanned_pages or nr_zones to stay constant.
	 * Also synchronizes pgdat->first_deferred_pfn during deferred page
	 * init.
	 *
	 * pgdat_resize_lock() and pgdat_resize_unlock() are provided to
	 * manipulate node_size_lock without checking for CONFIG_MEMORY_HOTPLUG
	 * or CONFIG_DEFERRED_STRUCT_PAGE_INIT.
	 *
	 * Nests above zone->lock and zone->span_seqlock
	 */
	spinlock_t node_size_lock;
#endif
	//这个节点的起始页号
	unsigned long node_start_pfn;
	//真正可用的物理页面的数目
	unsigned long node_present_pages; /* total number of physical pages */
	//这个节点中包含不连续的物理内存地址的页面数
	unsigned long node_spanned_pages; /* total size of physical page range, including holes */
	// ID 号
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	struct task_struct *kswapd;	/* Protected by
					   mem_hotplug_begin/end() */
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;

	int kswapd_failures;		/* Number of 'reclaimed == 0' runs */

#ifdef CONFIG_COMPACTION
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct *kcompactd;
	bool proactive_compact_trigger;
#endif
	/*
	 * This is a per-node reserve of pages that are not available
	 * to userspace allocations.
	 */
	unsigned long		totalreserve_pages;

#ifdef CONFIG_NUMA
	/*
	 * node reclaim becomes active if more unmapped pages exist.
	 */
	unsigned long		min_unmapped_pages;
	unsigned long		min_slab_pages;
#endif /* CONFIG_NUMA */

	/* Write-intensive fields used by page reclaim */
	ZONE_PADDING(_pad1_)

#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
	/*
	 * If memory initialisation on large machines is deferred then this
	 * is the first PFN that needs to be initialised.
	 */
	unsigned long first_deferred_pfn;
#endif /* CONFIG_DEFERRED_STRUCT_PAGE_INIT */

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	struct deferred_split deferred_split_queue;
#endif

	/* Fields commonly accessed by the page reclaim scanner */

	/*
	 * NOTE: THIS IS UNUSED IF MEMCG IS ENABLED.
	 *
	 * Use mem_cgroup_lruvec() to look up lruvecs.
	 */
	struct lruvec		__lruvec;

	unsigned long		flags;

	ZONE_PADDING(_pad2_)

	/* Per-node vmstats */
	struct per_cpu_nodestat __percpu *per_cpu_nodestats;
	atomic_long_t		vm_stat[NR_VM_NODE_STAT_ITEMS];
} pg_data_t;

#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#ifdef CONFIG_FLATMEM
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#else
#define pgdat_page_nr(pgdat, pagenr)	pfn_to_page((pgdat)->node_start_pfn + (pagenr))
#endif
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))

#define node_start_pfn(nid)	(NODE_DATA(nid)->node_start_pfn)
#define node_end_pfn(nid) pgdat_end_pfn(NODE_DATA(nid))

static inline unsigned long pgdat_end_pfn(pg_data_t *pgdat)
{
	return pgdat->node_start_pfn + pgdat->node_spanned_pages;
}

static inline bool pgdat_is_empty(pg_data_t *pgdat)
{
	return !pgdat->node_start_pfn && !pgdat->node_spanned_pages;
}

#include <linux/memory_hotplug.h>

void build_all_zonelists(pg_data_t *pgdat);
void wakeup_kswapd(struct zone *zone, gfp_t gfp_mask, int order,
		   enum zone_type highest_zoneidx);
bool __zone_watermark_ok(struct zone *z, unsigned int order, unsigned long mark,
			 int highest_zoneidx, unsigned int alloc_flags,
			 long free_pages);
bool zone_watermark_ok(struct zone *z, unsigned int order,
		unsigned long mark, int highest_zoneidx,
		unsigned int alloc_flags);
bool zone_watermark_ok_safe(struct zone *z, unsigned int order,
		unsigned long mark, int highest_zoneidx);
/*
 * Memory initialization context, use to differentiate memory added by
 * the platform statically or via memory hotplug interface.
 */
enum meminit_context {
	MEMINIT_EARLY,
	MEMINIT_HOTPLUG,
};

extern void init_currently_empty_zone(struct zone *zone, unsigned long start_pfn,
				     unsigned long size);

extern void lruvec_init(struct lruvec *lruvec);

static inline struct pglist_data *lruvec_pgdat(struct lruvec *lruvec)
{
#ifdef CONFIG_MEMCG
	return lruvec->pgdat;
#else
	return container_of(lruvec, struct pglist_data, __lruvec);
#endif
}

#ifdef CONFIG_HAVE_MEMORYLESS_NODES
int local_memory_node(int node_id);
#else
static inline int local_memory_node(int node_id) { return node_id; };
#endif

/*
 * zone_idx() returns 0 for the ZONE_DMA zone, 1 for the ZONE_NORMAL zone, etc.
 */
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)

#ifdef CONFIG_ZONE_DEVICE
static inline bool zone_is_zone_device(struct zone *zone)
{
	return zone_idx(zone) == ZONE_DEVICE;
}
#else
static inline bool zone_is_zone_device(struct zone *zone)
{
	return false;
}
#endif

/*
 * Returns true if a zone has pages managed by the buddy allocator.
 * All the reclaim decisions have to use this function rather than
 * populated_zone(). If the whole zone is reserved then we can easily
 * end up with populated_zone() && !managed_zone().
 */
static inline bool managed_zone(struct zone *zone)
{
	return zone_managed_pages(zone);
}

/* Returns true if a zone has memory */
static inline bool populated_zone(struct zone *zone)
{
	return zone->present_pages;
}

#ifdef CONFIG_NUMA
static inline int zone_to_nid(struct zone *zone)
{
	return zone->node;
}

static inline void zone_set_nid(struct zone *zone, int nid)
{
	zone->node = nid;
}
#else
static inline int zone_to_nid(struct zone *zone)
{
	return 0;
}

static inline void zone_set_nid(struct zone *zone, int nid) {}
#endif

extern int movable_zone;

static inline int is_highmem_idx(enum zone_type idx)
{
#ifdef CONFIG_HIGHMEM
	return (idx == ZONE_HIGHMEM ||
		(idx == ZONE_MOVABLE && movable_zone == ZONE_HIGHMEM));
#else
	return 0;
#endif
}

#ifdef CONFIG_ZONE_DMA
bool has_managed_dma(void);
#else
static inline bool has_managed_dma(void)
{
	return false;
}
#endif

/**
 * is_highmem - helper function to quickly check if a struct zone is a
 *              highmem zone or not.  This is an attempt to keep references
 *              to ZONE_{DMA/NORMAL/HIGHMEM/etc} in general code to a minimum.
 * @zone: pointer to struct zone variable
 * Return: 1 for a highmem zone, 0 otherwise
 */
static inline int is_highmem(struct zone *zone)
{
#ifdef CONFIG_HIGHMEM
	return is_highmem_idx(zone_idx(zone));
#else
	return 0;
#endif
}

/* These two functions are used to setup the per zone pages min values */
struct ctl_table;

int min_free_kbytes_sysctl_handler(struct ctl_table *, int, void *, size_t *,
		loff_t *);
int watermark_scale_factor_sysctl_handler(struct ctl_table *, int, void *,
		size_t *, loff_t *);
extern int sysctl_lowmem_reserve_ratio[MAX_NR_ZONES];
int lowmem_reserve_ratio_sysctl_handler(struct ctl_table *, int, void *,
		size_t *, loff_t *);
int percpu_pagelist_high_fraction_sysctl_handler(struct ctl_table *, int,
		void *, size_t *, loff_t *);
int sysctl_min_unmapped_ratio_sysctl_handler(struct ctl_table *, int,
		void *, size_t *, loff_t *);
int sysctl_min_slab_ratio_sysctl_handler(struct ctl_table *, int,
		void *, size_t *, loff_t *);
int numa_zonelist_order_handler(struct ctl_table *, int,
		void *, size_t *, loff_t *);
extern int percpu_pagelist_high_fraction;
extern char numa_zonelist_order[];
#define NUMA_ZONELIST_ORDER_LEN	16

#ifndef CONFIG_NUMA

extern struct pglist_data contig_page_data;
static inline struct pglist_data *NODE_DATA(int nid)
{
	return &contig_page_data;
}
#define NODE_MEM_MAP(nid)	mem_map

#else /* CONFIG_NUMA */

#include <asm/mmzone.h>

#endif /* !CONFIG_NUMA */

extern struct pglist_data *first_online_pgdat(void);
extern struct pglist_data *next_online_pgdat(struct pglist_data *pgdat);
extern struct zone *next_zone(struct zone *zone);

/**
 * for_each_online_pgdat - helper macro to iterate over all online nodes
 * @pgdat: pointer to a pg_data_t variable
 */
#define for_each_online_pgdat(pgdat)			\
	for (pgdat = first_online_pgdat();		\
	     pgdat;					\
	     pgdat = next_online_pgdat(pgdat))
/**
 * for_each_zone - helper macro to iterate over all memory zones
 * @zone: pointer to struct zone variable
 *
 * The user only needs to declare the zone variable, for_each_zone
 * fills it in.
 */
#define for_each_zone(zone)			        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))

#define for_each_populated_zone(zone)		        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))			\
		if (!populated_zone(zone))		\
			; /* do nothing */		\
		else

static inline struct zone *zonelist_zone(struct zoneref *zoneref)
{
	return zoneref->zone;
}

static inline int zonelist_zone_idx(struct zoneref *zoneref)
{
	return zoneref->zone_idx;
}

static inline int zonelist_node_idx(struct zoneref *zoneref)
{
	return zone_to_nid(zoneref->zone);
}

struct zoneref *__next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes);

/**
 * next_zones_zonelist - Returns the next zone at or below highest_zoneidx within the allowed nodemask using a cursor within a zonelist as a starting point
 * @z: The cursor used as a starting point for the search
 * @highest_zoneidx: The zone index of the highest zone to return
 * @nodes: An optional nodemask to filter the zonelist with
 *
 * This function returns the next zone at or below a given zone index that is
 * within the allowed nodemask using a cursor as the starting point for the
 * search. The zoneref returned is a cursor that represents the current zone
 * being examined. It should be advanced by one before calling
 * next_zones_zonelist again.
 *
 * Return: the next zone at or below highest_zoneidx within the allowed
 * nodemask using a cursor within a zonelist as a starting point
 */
static __always_inline struct zoneref *next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes)
{
	if (likely(!nodes && zonelist_zone_idx(z) <= highest_zoneidx))
		return z;
	return __next_zones_zonelist(z, highest_zoneidx, nodes);
}

/**
 * first_zones_zonelist - Returns the first zone at or below highest_zoneidx within the allowed nodemask in a zonelist
 * @zonelist: The zonelist to search for a suitable zone
 * @highest_zoneidx: The zone index of the highest zone to return
 * @nodes: An optional nodemask to filter the zonelist with
 *
 * This function returns the first zone at or below a given zone index that is
 * within the allowed nodemask. The zoneref returned is a cursor that can be
 * used to iterate the zonelist with next_zones_zonelist by advancing it by
 * one before calling.
 *
 * When no eligible zone is found, zoneref->zone is NULL (zoneref itself is
 * never NULL). This may happen either genuinely, or due to concurrent nodemask
 * update due to cpuset modification.
 *
 * Return: Zoneref pointer for the first suitable zone found
 */
static inline struct zoneref *first_zones_zonelist(struct zonelist *zonelist,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes)
{
	return next_zones_zonelist(zonelist->_zonerefs,
							highest_zoneidx, nodes);
}

/**
 * for_each_zone_zonelist_nodemask - helper macro to iterate over valid zones in a zonelist at or below a given zone index and within a nodemask
 * @zone: The current zone in the iterator
 * @z: The current pointer within zonelist->_zonerefs being iterated
 * @zlist: The zonelist being iterated
 * @highidx: The zone index of the highest zone to return
 * @nodemask: Nodemask allowed by the allocator
 *
 * This iterator iterates though all zones at or below a given zone index and
 * within a given nodemask
 */
#define for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, nodemask) \
	for (z = first_zones_zonelist(zlist, highidx, nodemask), zone = zonelist_zone(z);	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))

#define for_next_zone_zonelist_nodemask(zone, z, highidx, nodemask) \
	for (zone = z->zone;	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))


/**
 * for_each_zone_zonelist - helper macro to iterate over valid zones in a zonelist at or below a given zone index
 * @zone: The current zone in the iterator
 * @z: The current pointer within zonelist->zones being iterated
 * @zlist: The zonelist being iterated
 * @highidx: The zone index of the highest zone to return
 *
 * This iterator iterates though all zones at or below a given zone index.
 */
#define for_each_zone_zonelist(zone, z, zlist, highidx) \
	for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, NULL)

#ifdef CONFIG_SPARSEMEM
#include <asm/sparsemem.h>
#endif

#ifdef CONFIG_FLATMEM
#define pfn_to_nid(pfn)		(0)
#endif

#ifdef CONFIG_SPARSEMEM

/*
 * PA_SECTION_SHIFT		physical address to/from section number
 * PFN_SECTION_SHIFT		pfn to/from section number
 */
#define PA_SECTION_SHIFT	(SECTION_SIZE_BITS)
#define PFN_SECTION_SHIFT	(SECTION_SIZE_BITS - PAGE_SHIFT)

#define NR_MEM_SECTIONS		(1UL << SECTIONS_SHIFT)

#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define PAGE_SECTION_MASK	(~(PAGES_PER_SECTION-1))

#define SECTION_BLOCKFLAGS_BITS \
	((1UL << (PFN_SECTION_SHIFT - pageblock_order)) * NR_PAGEBLOCK_BITS)

#if (MAX_ORDER - 1 + PAGE_SHIFT) > SECTION_SIZE_BITS
#error Allocator MAX_ORDER exceeds SECTION_SIZE
#endif

static inline unsigned long pfn_to_section_nr(unsigned long pfn)
{
	return pfn >> PFN_SECTION_SHIFT;
}
static inline unsigned long section_nr_to_pfn(unsigned long sec)
{
	return sec << PFN_SECTION_SHIFT;
}

#define SECTION_ALIGN_UP(pfn)	(((pfn) + PAGES_PER_SECTION - 1) & PAGE_SECTION_MASK)
#define SECTION_ALIGN_DOWN(pfn)	((pfn) & PAGE_SECTION_MASK)

#define SUBSECTION_SHIFT 21
#define SUBSECTION_SIZE (1UL << SUBSECTION_SHIFT)

#define PFN_SUBSECTION_SHIFT (SUBSECTION_SHIFT - PAGE_SHIFT)
#define PAGES_PER_SUBSECTION (1UL << PFN_SUBSECTION_SHIFT)
#define PAGE_SUBSECTION_MASK (~(PAGES_PER_SUBSECTION-1))

#if SUBSECTION_SHIFT > SECTION_SIZE_BITS
#error Subsection size exceeds section size
#else
#define SUBSECTIONS_PER_SECTION (1UL << (SECTION_SIZE_BITS - SUBSECTION_SHIFT))
#endif

#define SUBSECTION_ALIGN_UP(pfn) ALIGN((pfn), PAGES_PER_SUBSECTION)
#define SUBSECTION_ALIGN_DOWN(pfn) ((pfn) & PAGE_SUBSECTION_MASK)

struct mem_section_usage {
	struct rcu_head rcu;
#ifdef CONFIG_SPARSEMEM_VMEMMAP
	DECLARE_BITMAP(subsection_map, SUBSECTIONS_PER_SECTION);
#endif
	/* See declaration of similar field in struct zone */
	unsigned long pageblock_flags[0];
};

void subsection_map_init(unsigned long pfn, unsigned long nr_pages);

struct page;
struct page_ext;
struct mem_section {
	/*
	 * This is, logically, a pointer to an array of struct
	 * pages.  However, it is stored with some other magic.
	 * (see sparse.c::sparse_init_one_section())
	 *
	 * Additionally during early boot we encode node id of
	 * the location of the section here to guide allocation.
	 * (see sparse.c::memory_present())
	 *
	 * Making it a UL at least makes someone do a cast
	 * before using it wrong.
	 */
	unsigned long section_mem_map;

	struct mem_section_usage *usage;
#ifdef CONFIG_PAGE_EXTENSION
	/*
	 * If SPARSEMEM, pgdat doesn't have page_ext pointer. We use
	 * section. (see page_ext.h about this.)
	 */
	struct page_ext *page_ext;
	unsigned long pad;
#endif
	/*
	 * WARNING: mem_section must be a power-of-2 in size for the
	 * calculation and use of SECTION_ROOT_MASK to make sense.
	 */
};

#ifdef CONFIG_SPARSEMEM_EXTREME
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#else
#define SECTIONS_PER_ROOT	1
#endif

#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define NR_SECTION_ROOTS	DIV_ROUND_UP(NR_MEM_SECTIONS, SECTIONS_PER_ROOT)
#define SECTION_ROOT_MASK	(SECTIONS_PER_ROOT - 1)

#ifdef CONFIG_SPARSEMEM_EXTREME
extern struct mem_section **mem_section;
#else
extern struct mem_section mem_section[NR_SECTION_ROOTS][SECTIONS_PER_ROOT];
#endif

static inline unsigned long *section_to_usemap(struct mem_section *ms)
{
	return ms->usage->pageblock_flags;
}

static inline struct mem_section *__nr_to_section(unsigned long nr)
{
	unsigned long root = SECTION_NR_TO_ROOT(nr);

	if (unlikely(root >= NR_SECTION_ROOTS))
		return NULL;

#ifdef CONFIG_SPARSEMEM_EXTREME
	if (!mem_section || !mem_section[root])
		return NULL;
#endif
	return &mem_section[root][nr & SECTION_ROOT_MASK];
}
extern size_t mem_section_usage_size(void);

/*
 * We use the lower bits of the mem_map pointer to store
 * a little bit of information.  The pointer is calculated
 * as mem_map - section_nr_to_pfn(pnum).  The result is
 * aligned to the minimum alignment of the two values:
 *   1. All mem_map arrays are page-aligned.
 *   2. section_nr_to_pfn() always clears PFN_SECTION_SHIFT
 *      lowest bits.  PFN_SECTION_SHIFT is arch-specific
 *      (equal SECTION_SIZE_BITS - PAGE_SHIFT), and the
 *      worst combination is powerpc with 256k pages,
 *      which results in PFN_SECTION_SHIFT equal 6.
 * To sum it up, at least 6 bits are available.
 */
#define SECTION_MARKED_PRESENT		(1UL<<0)
#define SECTION_HAS_MEM_MAP		(1UL<<1)
#define SECTION_IS_ONLINE		(1UL<<2)
#define SECTION_IS_EARLY		(1UL<<3)
#define SECTION_TAINT_ZONE_DEVICE	(1UL<<4)
#define SECTION_MAP_LAST_BIT		(1UL<<5)
#define SECTION_MAP_MASK		(~(SECTION_MAP_LAST_BIT-1))
#define SECTION_NID_SHIFT		6

static inline struct page *__section_mem_map_addr(struct mem_section *section)
{
	unsigned long map = section->section_mem_map;
	map &= SECTION_MAP_MASK;
	return (struct page *)map;
}

static inline int present_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_MARKED_PRESENT));
}

static inline int present_section_nr(unsigned long nr)
{
	return present_section(__nr_to_section(nr));
}

static inline int valid_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_HAS_MEM_MAP));
}

static inline int early_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_IS_EARLY));
}

static inline int valid_section_nr(unsigned long nr)
{
	return valid_section(__nr_to_section(nr));
}

static inline int online_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_IS_ONLINE));
}

static inline int online_device_section(struct mem_section *section)
{
	unsigned long flags = SECTION_IS_ONLINE | SECTION_TAINT_ZONE_DEVICE;

	return section && ((section->section_mem_map & flags) == flags);
}

static inline int online_section_nr(unsigned long nr)
{
	return online_section(__nr_to_section(nr));
}

#ifdef CONFIG_MEMORY_HOTPLUG
void online_mem_sections(unsigned long start_pfn, unsigned long end_pfn);
void offline_mem_sections(unsigned long start_pfn, unsigned long end_pfn);
#endif

static inline struct mem_section *__pfn_to_section(unsigned long pfn)
{
	return __nr_to_section(pfn_to_section_nr(pfn));
}

extern unsigned long __highest_present_section_nr;

static inline int subsection_map_index(unsigned long pfn)
{
	return (pfn & ~(PAGE_SECTION_MASK)) / PAGES_PER_SUBSECTION;
}

#ifdef CONFIG_SPARSEMEM_VMEMMAP
static inline int pfn_section_valid(struct mem_section *ms, unsigned long pfn)
{
	int idx = subsection_map_index(pfn);
	struct mem_section_usage *usage = READ_ONCE(ms->usage);

	return usage ? test_bit(idx, usage->subsection_map) : 0;
}
#else
static inline int pfn_section_valid(struct mem_section *ms, unsigned long pfn)
{
	return 1;
}
#endif

#ifndef CONFIG_HAVE_ARCH_PFN_VALID
/**
 * pfn_valid - check if there is a valid memory map entry for a PFN
 * @pfn: the page frame number to check
 *
 * Check if there is a valid memory map entry aka struct page for the @pfn.
 * Note, that availability of the memory map entry does not imply that
 * there is actual usable memory at that @pfn. The struct page may
 * represent a hole or an unusable page frame.
 *
 * Return: 1 for PFNs that have memory map entries and 0 otherwise
 */
static inline int pfn_valid(unsigned long pfn)
{
	struct mem_section *ms;
	int ret;

	/*
	 * Ensure the upper PAGE_SHIFT bits are clear in the
	 * pfn. Else it might lead to false positives when
	 * some of the upper bits are set, but the lower bits
	 * match a valid pfn.
	 */
	if (PHYS_PFN(PFN_PHYS(pfn)) != pfn)
		return 0;

	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	ms = __pfn_to_section(pfn);
	rcu_read_lock();
	if (!valid_section(ms)) {
		rcu_read_unlock();
		return 0;
	}
	/*
	 * Traditionally early sections always returned pfn_valid() for
	 * the entire section-sized span.
	 */
	ret = early_section(ms) || pfn_section_valid(ms, pfn);
	rcu_read_unlock();

	return ret;
}
#endif

static inline int pfn_in_present_section(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return present_section(__pfn_to_section(pfn));
}

static inline unsigned long next_present_section_nr(unsigned long section_nr)
{
	while (++section_nr <= __highest_present_section_nr) {
		if (present_section_nr(section_nr))
			return section_nr;
	}

	return -1;
}

/*
 * These are _only_ used during initialisation, therefore they
 * can use __initdata ...  They could have names to indicate
 * this restriction.
 */
#ifdef CONFIG_NUMA
#define pfn_to_nid(pfn)							\
({									\
	unsigned long __pfn_to_nid_pfn = (pfn);				\
	page_to_nid(pfn_to_page(__pfn_to_nid_pfn));			\
})
#else
#define pfn_to_nid(pfn)		(0)
#endif

void sparse_init(void);
#else
#define sparse_init()	do {} while (0)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#define pfn_in_present_section pfn_valid
#define subsection_map_init(_pfn, _nr_pages) do {} while (0)
#endif /* CONFIG_SPARSEMEM */

#endif /* !__GENERATING_BOUNDS.H */
#endif /* !__ASSEMBLY__ */
#endif /* _LINUX_MMZONE_H */
