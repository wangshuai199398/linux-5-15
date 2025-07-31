// SPDX-License-Identifier: GPL-2.0
/*
 *  prepare to run common code
 *
 *  Copyright (C) 2000 Andrea Arcangeli <andrea@suse.de> SuSE
 */

#define DISABLE_BRANCH_PROFILING

/* cpu_feature_enabled() cannot be used this early */
#define USE_EARLY_PGTABLE_L5

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/percpu.h>
#include <linux/start_kernel.h>
#include <linux/io.h>
#include <linux/memblock.h>
#include <linux/mem_encrypt.h>
#include <linux/pgtable.h>

#include <asm/processor.h>
#include <asm/proto.h>
#include <asm/smp.h>
#include <asm/setup.h>
#include <asm/desc.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/kdebug.h>
#include <asm/e820/api.h>
#include <asm/bios_ebda.h>
#include <asm/bootparam_utils.h>
#include <asm/microcode.h>
#include <asm/kasan.h>
#include <asm/fixmap.h>
#include <asm/realmode.h>
#include <asm/extable.h>
#include <asm/trapnr.h>
#include <asm/sev.h>

/*
 * Manage page tables very early on.
 */
extern pmd_t early_dynamic_pgts[EARLY_DYNAMIC_PAGE_TABLES][PTRS_PER_PMD];
static unsigned int __initdata next_early_pgt;
pmdval_t early_pmd_flags = __PAGE_KERNEL_LARGE & ~(_PAGE_GLOBAL | _PAGE_NX);

#ifdef CONFIG_X86_5LEVEL
unsigned int __pgtable_l5_enabled __ro_after_init;
unsigned int pgdir_shift __ro_after_init = 39;
EXPORT_SYMBOL(pgdir_shift);
unsigned int ptrs_per_p4d __ro_after_init = 1;
EXPORT_SYMBOL(ptrs_per_p4d);
#endif

#ifdef CONFIG_DYNAMIC_MEMORY_LAYOUT
unsigned long page_offset_base __ro_after_init = __PAGE_OFFSET_BASE_L4;
EXPORT_SYMBOL(page_offset_base);
unsigned long vmalloc_base __ro_after_init = __VMALLOC_BASE_L4;
EXPORT_SYMBOL(vmalloc_base);
unsigned long vmemmap_base __ro_after_init = __VMEMMAP_BASE_L4;
EXPORT_SYMBOL(vmemmap_base);
#endif

/*
 * GDT used on the boot CPU before switching to virtual addresses.
 */
static struct desc_struct startup_gdt[GDT_ENTRIES] = {
	[GDT_ENTRY_KERNEL32_CS]         = GDT_ENTRY_INIT(0xc09b, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_CS]           = GDT_ENTRY_INIT(0xa09b, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_DS]           = GDT_ENTRY_INIT(0xc093, 0, 0xfffff),
};

/*
 * Address needs to be set at runtime because it references the startup_gdt
 * while the kernel still uses a direct mapping.
 */
static struct desc_ptr startup_gdt_descr = {
	.size = sizeof(startup_gdt)-1,
	.address = 0,
};

#define __head	__section(".head.text")

static void __head *fixup_pointer(void *ptr, unsigned long physaddr)
{
	return ptr - (void *)_text + (void *)physaddr;
}

static unsigned long __head *fixup_long(void *ptr, unsigned long physaddr)
{
	return fixup_pointer(ptr, physaddr);
}

#ifdef CONFIG_X86_5LEVEL
static unsigned int __head *fixup_int(void *ptr, unsigned long physaddr)
{
	return fixup_pointer(ptr, physaddr);
}

static bool __head check_la57_support(unsigned long physaddr)
{
	/*
	 * 5-level paging is detected and enabled at kernel decompression
	 * stage. Only check if it has been enabled there.
	 */
	if (!(native_read_cr4() & X86_CR4_LA57))
		return false;

	*fixup_int(&__pgtable_l5_enabled, physaddr) = 1;
	*fixup_int(&pgdir_shift, physaddr) = 48;
	*fixup_int(&ptrs_per_p4d, physaddr) = 512;
	*fixup_long(&page_offset_base, physaddr) = __PAGE_OFFSET_BASE_L5;
	*fixup_long(&vmalloc_base, physaddr) = __VMALLOC_BASE_L5;
	*fixup_long(&vmemmap_base, physaddr) = __VMEMMAP_BASE_L5;

	return true;
}
#else
static bool __head check_la57_support(unsigned long physaddr)
{
	return false;
}
#endif

/* Code in __startup_64() can be relocated during execution, but the compiler
 * doesn't have to generate PC-relative relocations when accessing globals from
 * that function. Clang actually does not generate them, which leads to
 * boot-time crashes. To work around this problem, every global pointer must
 * be adjusted using fixup_pointer().
 */
unsigned long __head __startup_64(unsigned long physaddr,
				  struct boot_params *bp)
{
	unsigned long vaddr, vaddr_end;
	unsigned long load_delta, *p;
	unsigned long pgtable_flags;
	pgdval_t *pgd;
	p4dval_t *p4d;
	pudval_t *pud;
	pmdval_t *pmd, pmd_entry;
	pteval_t *mask_ptr;
	bool la57;
	int i;
	unsigned int *next_pgt_ptr;

	la57 = check_la57_support(physaddr);

	/* Is the address too large? */
	if (physaddr >> MAX_PHYSMEM_BITS)
		for (;;);

	/*
	 * Compute the delta between the address I am compiled to run at
	 * and the address I am actually running at.
	 */
	load_delta = physaddr - (unsigned long)(_text - __START_KERNEL_map);

	/* Is the address not 2M aligned? */
	if (load_delta & ~PMD_PAGE_MASK)
		for (;;);

	/* Activate Secure Memory Encryption (SME) if supported and enabled */
	sme_enable(bp);

	/* Include the SME encryption mask in the fixup value */
	load_delta += sme_get_me_mask();

	/* Fixup the physical addresses in the page table */

	pgd = fixup_pointer(&early_top_pgt, physaddr);
	p = pgd + pgd_index(__START_KERNEL_map);
	if (la57)
		*p = (unsigned long)level4_kernel_pgt;
	else
		*p = (unsigned long)level3_kernel_pgt;
	*p += _PAGE_TABLE_NOENC - __START_KERNEL_map + load_delta;

	if (la57) {
		p4d = fixup_pointer(&level4_kernel_pgt, physaddr);
		p4d[511] += load_delta;
	}

	pud = fixup_pointer(&level3_kernel_pgt, physaddr);
	pud[510] += load_delta;
	pud[511] += load_delta;

	pmd = fixup_pointer(level2_fixmap_pgt, physaddr);
	for (i = FIXMAP_PMD_TOP; i > FIXMAP_PMD_TOP - FIXMAP_PMD_NUM; i--)
		pmd[i] += load_delta;

	/*
	 * Set up the identity mapping for the switchover.  These
	 * entries should *NOT* have the global bit set!  This also
	 * creates a bunch of nonsense entries but that is fine --
	 * it avoids problems around wraparound.
	 */

	next_pgt_ptr = fixup_pointer(&next_early_pgt, physaddr);
	pud = fixup_pointer(early_dynamic_pgts[(*next_pgt_ptr)++], physaddr);
	pmd = fixup_pointer(early_dynamic_pgts[(*next_pgt_ptr)++], physaddr);

	pgtable_flags = _KERNPG_TABLE_NOENC + sme_get_me_mask();

	if (la57) {
		p4d = fixup_pointer(early_dynamic_pgts[(*next_pgt_ptr)++],
				    physaddr);

		i = (physaddr >> PGDIR_SHIFT) % PTRS_PER_PGD;
		pgd[i + 0] = (pgdval_t)p4d + pgtable_flags;
		pgd[i + 1] = (pgdval_t)p4d + pgtable_flags;

		i = physaddr >> P4D_SHIFT;
		p4d[(i + 0) % PTRS_PER_P4D] = (pgdval_t)pud + pgtable_flags;
		p4d[(i + 1) % PTRS_PER_P4D] = (pgdval_t)pud + pgtable_flags;
	} else {
		i = (physaddr >> PGDIR_SHIFT) % PTRS_PER_PGD;
		pgd[i + 0] = (pgdval_t)pud + pgtable_flags;
		pgd[i + 1] = (pgdval_t)pud + pgtable_flags;
	}

	i = physaddr >> PUD_SHIFT;
	pud[(i + 0) % PTRS_PER_PUD] = (pudval_t)pmd + pgtable_flags;
	pud[(i + 1) % PTRS_PER_PUD] = (pudval_t)pmd + pgtable_flags;

	pmd_entry = __PAGE_KERNEL_LARGE_EXEC & ~_PAGE_GLOBAL;
	/* Filter out unsupported __PAGE_KERNEL_* bits: */
	mask_ptr = fixup_pointer(&__supported_pte_mask, physaddr);
	pmd_entry &= *mask_ptr;
	pmd_entry += sme_get_me_mask();
	pmd_entry +=  physaddr;

	for (i = 0; i < DIV_ROUND_UP(_end - _text, PMD_SIZE); i++) {
		int idx = i + (physaddr >> PMD_SHIFT);

		pmd[idx % PTRS_PER_PMD] = pmd_entry + i * PMD_SIZE;
	}

	/*
	 * Fixup the kernel text+data virtual addresses. Note that
	 * we might write invalid pmds, when the kernel is relocated
	 * cleanup_highmap() fixes this up along with the mappings
	 * beyond _end.
	 *
	 * Only the region occupied by the kernel image has so far
	 * been checked against the table of usable memory regions
	 * provided by the firmware, so invalidate pages outside that
	 * region. A page table entry that maps to a reserved area of
	 * memory would allow processor speculation into that area,
	 * and on some hardware (particularly the UV platform) even
	 * speculative access to some reserved areas is caught as an
	 * error, causing the BIOS to halt the system.
	 */

	pmd = fixup_pointer(level2_kernel_pgt, physaddr);

	/* invalidate pages before the kernel image */
	for (i = 0; i < pmd_index((unsigned long)_text); i++)
		pmd[i] &= ~_PAGE_PRESENT;

	/* fixup pages that are part of the kernel image */
	for (; i <= pmd_index((unsigned long)_end); i++)
		if (pmd[i] & _PAGE_PRESENT)
			pmd[i] += load_delta;

	/* invalidate pages after the kernel image */
	for (; i < PTRS_PER_PMD; i++)
		pmd[i] &= ~_PAGE_PRESENT;

	/*
	 * Fixup phys_base - remove the memory encryption mask to obtain
	 * the true physical address.
	 */
	*fixup_long(&phys_base, physaddr) += load_delta - sme_get_me_mask();

	/* Encrypt the kernel and related (if SME is active) */
	sme_encrypt_kernel(bp);

	/*
	 * Clear the memory encryption mask from the .bss..decrypted section.
	 * The bss section will be memset to zero later in the initialization so
	 * there is no need to zero it after changing the memory encryption
	 * attribute.
	 */
	if (mem_encrypt_active()) {
		vaddr = (unsigned long)__start_bss_decrypted;
		vaddr_end = (unsigned long)__end_bss_decrypted;
		for (; vaddr < vaddr_end; vaddr += PMD_SIZE) {
			i = pmd_index(vaddr);
			pmd[i] -= sme_get_me_mask();
		}
	}

	/*
	 * Return the SME encryption mask (if SME is active) to be used as a
	 * modifier for the initial pgdir entry programmed into CR3.
	 */
	return sme_get_me_mask();
}

unsigned long __startup_secondary_64(void)
{
	/*
	 * Return the SME encryption mask (if SME is active) to be used as a
	 * modifier for the initial pgdir entry programmed into CR3.
	 */
	return sme_get_me_mask();
}

/* Wipe all early page tables except for the kernel symbol map */
static void __init reset_early_page_tables(void)
{
	memset(early_top_pgt, 0, sizeof(pgd_t)*(PTRS_PER_PGD-1));
	next_early_pgt = 0;
	write_cr3(__sme_pa_nodebug(early_top_pgt));
}

/* Create a new PMD entry
   PGD   Page Global Directory      页全局目录，顶层目录
   P4D   Page 4th-level Directory   第四层目录（在 5 级页表中才启用）
   PUD   Page Upper Directory       上层目录
   PMD   Page Middle Directory      中间目录
   PTE   Page Table Entry           最终指向物理页的条目（叶子节点）
*/
bool __init __early_make_pgtable(unsigned long address, pmdval_t pmd)
{
	unsigned long physaddr = address - __PAGE_OFFSET;
	pgdval_t pgd, *pgd_p;
	p4dval_t p4d, *p4d_p;
	pudval_t pud, *pud_p;
	pmdval_t *pmd_p;

	/* Invalid address or early pgt is done ?  */
	if (physaddr >= MAXMEM || read_cr3_pa() != __pa_nodebug(early_top_pgt))
		return false;

again:
	//取得页表中包含引起 #PF 中断的地址的那一项，将其赋值给 pgd 变量
	pgd_p = &early_top_pgt[pgd_index(address)].pgd;
	pgd = *pgd_p;

	/*
	 * The use of __START_KERNEL_map rather than __PAGE_OFFSET here is
	 * critical -- __PAGE_OFFSET would point us back into the dynamic
	 * range and we might end up looping forever...
	 */
	if (!pgtable_l5_enabled())
		p4d_p = pgd_p;
	else if (pgd)
		//如果它包含了正确的全局页表项的话，我们就把这一项的物理地址处理后赋值
		p4d_p = (p4dval_t *)((pgd & PTE_PFN_MASK) + __START_KERNEL_map - phys_base);
	else {
		/*
		如果 pgd 没有包含有效的地址，我们就检查 next_early_pgt 与 EARLY_DYNAMIC_PAGE_TABLES（即 64 ）的大小
		EARLY_DYNAMIC_PAGE_TABLES 它是一个固定大小的缓冲区，用来在需要的时候建立新的页表
		如果 next_early_pgt 比 EARLY_DYNAMIC_PAGE_TABLES 大，我们就用一个上层页目录指针指向当前的动态页表，并将它的物理地址与 _KERPG_TABLE 访问权限一起写入全局页目录表
		*/
		if (next_early_pgt >= EARLY_DYNAMIC_PAGE_TABLES) {
			reset_early_page_tables();
			goto again;
		}

		p4d_p = (p4dval_t *)early_dynamic_pgts[next_early_pgt++];
		memset(p4d_p, 0, sizeof(*p4d_p) * PTRS_PER_P4D);
		*pgd_p = (pgdval_t)p4d_p - __START_KERNEL_map + phys_base + _KERNPG_TABLE;
	}
	p4d_p += p4d_index(address);
	p4d = *p4d_p;

	if (p4d)
		pud_p = (pudval_t *)((p4d & PTE_PFN_MASK) + __START_KERNEL_map - phys_base);
	else {
		if (next_early_pgt >= EARLY_DYNAMIC_PAGE_TABLES) {
			reset_early_page_tables();
			goto again;
		}

		pud_p = (pudval_t *)early_dynamic_pgts[next_early_pgt++];
		memset(pud_p, 0, sizeof(*pud_p) * PTRS_PER_PUD);
		*p4d_p = (p4dval_t)pud_p - __START_KERNEL_map + phys_base + _KERNPG_TABLE;
	}
	//修正上层页目录的地址
	pud_p += pud_index(address);
	pud = *pud_p;
	//对中层页目录重复上面同样的操作
	if (pud)
		pmd_p = (pmdval_t *)((pud & PTE_PFN_MASK) + __START_KERNEL_map - phys_base);
	else {
		if (next_early_pgt >= EARLY_DYNAMIC_PAGE_TABLES) {
			reset_early_page_tables();
			goto again;
		}

		pmd_p = (pmdval_t *)early_dynamic_pgts[next_early_pgt++];
		memset(pmd_p, 0, sizeof(*pmd_p) * PTRS_PER_PMD);
		*pud_p = (pudval_t)pmd_p - __START_KERNEL_map + phys_base + _KERNPG_TABLE;
	}
	pmd_p[pmd_index(address)] = pmd;

	return true;
}
//缺页中断
static bool __init early_make_pgtable(unsigned long address)
{
	unsigned long physaddr = address - __PAGE_OFFSET;
	pmdval_t pmd;

	pmd = (physaddr & PMD_MASK) + early_pmd_flags;

	return __early_make_pgtable(address, pmd);
}

void __init do_early_exception(struct pt_regs *regs, int trapnr)
{
	if (trapnr == X86_TRAP_PF &&
	    early_make_pgtable(native_read_cr2()))
		return;

	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT) &&
	    trapnr == X86_TRAP_VC && handle_vc_boot_ghcb(regs))
		return;

	early_fixup_exception(regs, trapnr);
}

/* Don't add a printk in there. printk relies on the PDA which is not initialized 
   yet. */
static void __init clear_bss(void)
{
	memset(__bss_start, 0,
	       (unsigned long) __bss_stop - (unsigned long) __bss_start);
	memset(__brk_base, 0,
	       (unsigned long) __brk_limit - (unsigned long) __brk_base);
}

static unsigned long get_cmd_line_ptr(void)
{
	unsigned long cmd_line_ptr = boot_params.hdr.cmd_line_ptr;

	cmd_line_ptr |= (u64)boot_params.ext_cmd_line_ptr << 32;

	return cmd_line_ptr;
}
/*
__init: 表示这个函数只在初始化阶段使用，并且它所使用的内存将会被释放
*/
static void __init copy_bootdata(char *real_mode_data)
{
	char * command_line;
	unsigned long cmd_line_ptr;

	/*
	 * If SME is active, this will create decrypted mappings of the
	 * boot data in advance of the copy operations.
	 */
	sme_map_bootdata(real_mode_data);

	memcpy(&boot_params, real_mode_data, sizeof(boot_params));
	//对成员进行清零
	sanitize_boot_params(&boot_params);
	//得到命令行的地址
	cmd_line_ptr = get_cmd_line_ptr();
	if (cmd_line_ptr) {
		//把它的虚拟地址拷贝到一个字节数组 boot_command_line 中
		command_line = __va(cmd_line_ptr);
		memcpy(boot_command_line, command_line, COMMAND_LINE_SIZE);
	}

	/*
	 * The old boot data is no longer needed and won't be reserved,
	 * freeing up that memory for use by the system. If SME is active,
	 * we need to remove the mappings that were created so that the
	 * memory doesn't remain mapped as decrypted.
	 */
	sme_unmap_bootdata(real_mode_data);
}

/* 系统启动 start_kernel_wangs
   Linux 内核进入正式 C 语言环境的起点（在 64 位系统）
	BIOS/UEFI
		|
	Bootloader(GRUB, etc.)
		|
	Linux kernel(in compressed form)
		|
	arch/x86/boot/compressed/head_64.S
		|
	decompress kernel -> jump to x86_64_start_kernel
		|
	x86_64_start_kernel -> start_kernel()
		|
	初始化子系统、驱动、挂载根文件系统
		|
	启动 init 进程(PID 1)

	real_mode_data: boot_params 结构体的虚拟地址
*/
asmlinkage __visible void __init x86_64_start_kernel(char * real_mode_data)
{
	/* 内核编译（构建）阶段时核映像和模块区域映射的一致性检查 
	   模块的虚拟地址不能低于内核 text 段基地址 __START_KERNEL_map
	   包含模块的内核 text 段的空间大小不能小于内核镜像大小 等
	*/
	BUILD_BUG_ON(MODULES_VADDR < __START_KERNEL_map);
	BUILD_BUG_ON(MODULES_VADDR - __START_KERNEL_map < KERNEL_IMAGE_SIZE);
	BUILD_BUG_ON(MODULES_LEN + KERNEL_IMAGE_SIZE > 2*PUD_SIZE);
	BUILD_BUG_ON((__START_KERNEL_map & ~PMD_MASK) != 0);
	BUILD_BUG_ON((MODULES_VADDR & ~PMD_MASK) != 0);
	BUILD_BUG_ON(!(MODULES_VADDR > __START_KERNEL));
	MAYBE_BUILD_BUG_ON(!(((MODULES_END - 1) & PGDIR_MASK) ==
				(__START_KERNEL & PGDIR_MASK)));
	BUILD_BUG_ON(__fix_to_virt(__end_of_fixed_addresses) <= MODULES_END);
	//存储了每个CPU中 cr4 的Shadow Copy, 上下文切换可能会修改 cr4 中的位，因此需要保存每个CPU中 cr4 的内容
	cr4_init_shadow();

	/* 重置了所有的全局页目录项，同时向 cr3 中重新写入了的全局页目录表的地址 */
	reset_early_page_tables();
	//清空了从 __bss_stop 到 __bss_start 的 _bss 段，下一步将是建立初期 IDT（中断描述符表） 的处理代码
	clear_bss();

	clear_page(init_top_pgt);

	/*
	 * SME support may update early_pmd_flags to include the memory
	 * encryption mask, so it needs to be called before anything
	 * that may generate a page fault.
	 */
	sme_early_init();

	kasan_early_init();
	//中断描述符表早期设置
	idt_setup_early_handler();
	//把 real_mod_data （定义在 arch/x86/kernel/setup.h） 拷贝进 boot_params
	copy_bootdata(__va(real_mode_data));

	/* Load microcode early on BSP. 加载处理器微代码 */
	load_ucode_bsp();

	/* set init_top_pgt kernel high mapping*/
	init_top_pgt[511] = early_top_pgt[511];

	x86_64_start_reservations(real_mode_data);
}

void __init x86_64_start_reservations(char *real_mode_data)
{
	/* version is always not zero if it is copied */
	if (!boot_params.hdr.version)
		copy_bootdata(__va(real_mode_data));

	x86_early_init_platform_quirks();

	switch (boot_params.hdr.hardware_subarch) {
	case X86_SUBARCH_INTEL_MID:
		x86_intel_mid_early_setup();
		break;
	default:
		break;
	}

	start_kernel();
}

/*
 * 用于 IDT（中断描述符表）设置的数据结构和代码位于 head_64.S 中
 * 在正式使用 idt_table 之前，系统会使用一个 临时的 bringup-IDT
 * 对于 引导 CPU（BSP），这个切换过程发生在 x86_64_start_kernel() 中
 * 对于 其他的辅助 CPU（AP），这个切换过程发生在 start_secondary() 中
 * 两种情况中的函数调用都源自 head_64.S
 *
 * idt_table 在内核启动的早期阶段不能直接使用，原因如下：
 * 1. 所有对 idt_table 的修改操作都在 idt.c 中进行，而这些操作可能被追踪（tracing）或 KASAN（内核地址消毒器）检测；
 * 2. 而在早期 CPU 启动阶段，追踪和 KASAN 都还没准备好；
 * 3. 此外，idt_table 设置的是运行时的中断向量（runtime vectors），这些向量需要特定的 CPU 状态（例如 TSS，任务状态段）才能正常使用；
 * 4. 而这些状态在早期 CPU 启动阶段也尚未初始化。
 * 总结一句话：
 * 		在 Linux 内核的早期启动阶段，系统先使用临时 IDT 来处理中断，因为真正的 IDT 依赖于系统后续才能提供的功能和状态。
 */
static gate_desc bringup_idt_table[NUM_EXCEPTION_VECTORS] __page_aligned_data;

static struct desc_ptr bringup_idt_descr = {
	.size		= (NUM_EXCEPTION_VECTORS * sizeof(gate_desc)) - 1,
	.address	= 0, /* Set at runtime */
};

static void set_bringup_idt_handler(gate_desc *idt, int n, void *handler)
{
#ifdef CONFIG_AMD_MEM_ENCRYPT
	struct idt_data data;
	gate_desc desc;

	init_idt_data(&data, n, handler);
	idt_init_desc(&desc, &data);
	native_write_idt_entry(idt, n, &desc);
#endif
}

/* This runs while still in the direct mapping */
static void startup_64_load_idt(unsigned long physbase)
{
	struct desc_ptr *desc = fixup_pointer(&bringup_idt_descr, physbase);
	gate_desc *idt = fixup_pointer(bringup_idt_table, physbase);


	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
		void *handler;

		/* VMM Communication Exception */
		handler = fixup_pointer(vc_no_ghcb, physbase);
		set_bringup_idt_handler(idt, X86_TRAP_VC, handler);
	}

	desc->address = (unsigned long)idt;
	native_load_idt(desc);
}

/* This is used when running on kernel addresses */
void early_setup_idt(void)
{
	/* VMM Communication Exception */
	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT))
		set_bringup_idt_handler(bringup_idt_table, X86_TRAP_VC, vc_boot_ghcb);

	bringup_idt_descr.address = (unsigned long)bringup_idt_table;
	native_load_idt(&bringup_idt_descr);
}

/*
 * Setup boot CPU state needed before kernel switches to virtual addresses.
 */
void __head startup_64_setup_env(unsigned long physbase)
{
	/* Load GDT */
	startup_gdt_descr.address = (unsigned long)fixup_pointer(startup_gdt, physbase);
	native_load_gdt(&startup_gdt_descr);

	/* New GDT is live - reload data segment registers */
	asm volatile("movl %%eax, %%ds\n"
		     "movl %%eax, %%ss\n"
		     "movl %%eax, %%es\n" : : "a"(__KERNEL_DS) : "memory");

	startup_64_load_idt(physbase);
}
