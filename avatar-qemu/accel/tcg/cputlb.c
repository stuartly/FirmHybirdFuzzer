/*
 *  Common CPU TLB handling
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "exec/cpu_ldst.h"
#include "exec/cputlb.h"
#include "exec/memory-internal.h"
#include "exec/ram_addr.h"
#include "tcg/tcg.h"
#include "qemu/error-report.h"
#include "exec/log.h"
#include "exec/helper-proto.h"
#include "qemu/atomic.h"

#include "qemu/log.h"
/* DEBUG defines, enable DEBUG_TLB_LOG to log to the CPU_LOG_MMU target */
/* #define DEBUG_TLB */
/* #define DEBUG_TLB_LOG */

#ifdef DEBUG_TLB
# define DEBUG_TLB_GATE 1
# ifdef DEBUG_TLB_LOG
#  define DEBUG_TLB_LOG_GATE 1
# else
#  define DEBUG_TLB_LOG_GATE 0
# endif
#else
# define DEBUG_TLB_GATE 0
# define DEBUG_TLB_LOG_GATE 0
#endif

#define tlb_debug(fmt, ...) do { \
    if (DEBUG_TLB_LOG_GATE) { \
        qemu_log_mask(CPU_LOG_MMU, "%s: " fmt, __func__, \
                      ## __VA_ARGS__); \
    } else if (DEBUG_TLB_GATE) { \
        fprintf(stderr, "%s: " fmt, __func__, ## __VA_ARGS__); \
    } \
} while (0)

#define assert_cpu_is_self(this_cpu) do {                         \
        if (DEBUG_TLB_GATE) {                                     \
            g_assert(!cpu->created || qemu_cpu_is_self(cpu));     \
        }                                                         \
    } while (0)

/* run_on_cpu_data.target_ptr should always be big enough for a
 * target_ulong even on 32 bit builds */
QEMU_BUILD_BUG_ON(sizeof(target_ulong) > sizeof(run_on_cpu_data));

/* We currently can't handle more than 16 bits in the MMUIDX bitmask.
 */
QEMU_BUILD_BUG_ON(NB_MMU_MODES > 16);
#define ALL_MMUIDX_BITS ((1 << NB_MMU_MODES) - 1)

/* flush_all_helper: run fn across all cpus
 *
 * If the wait flag is set then the src cpu's helper will be queued as
 * "safe" work and the loop exited creating a synchronisation point
 * where all queued work will be finished before execution starts
 * again.
 */
static void flush_all_helper(CPUState *src, run_on_cpu_func fn,
                             run_on_cpu_data d)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (cpu != src) {
            async_run_on_cpu(cpu, fn, d);
        }
    }
}

size_t tlb_flush_count(void)
{
    CPUState *cpu;
    size_t count = 0;

    CPU_FOREACH(cpu) {
        CPUArchState *env = cpu->env_ptr;

        count += atomic_read(&env->tlb_flush_count);
    }
    return count;
}

/* This is OK because CPU architectures generally permit an
 * implementation to drop entries from the TLB at any time, so
 * flushing more entries than required is only an efficiency issue,
 * not a correctness issue.
 */
static void tlb_flush_nocheck(CPUState *cpu)
{
    CPUArchState *env = cpu->env_ptr;

    /* The QOM tests will trigger tlb_flushes without setting up TCG
     * so we bug out here in that case.
     */
    if (!tcg_enabled()) {
        return;
    }

    assert_cpu_is_self(cpu);
    atomic_set(&env->tlb_flush_count, env->tlb_flush_count + 1);
    tlb_debug("(count: %zu)\n", tlb_flush_count());

    memset(env->tlb_table, -1, sizeof(env->tlb_table));
    memset(env->tlb_v_table, -1, sizeof(env->tlb_v_table));
    cpu_tb_jmp_cache_clear(cpu);

    env->vtlb_index = 0;
    env->tlb_flush_addr = -1;
    env->tlb_flush_mask = 0;

    atomic_mb_set(&cpu->pending_tlb_flush, 0);
}

static void tlb_flush_global_async_work(CPUState *cpu, run_on_cpu_data data)
{
    tlb_flush_nocheck(cpu);
}

void tlb_flush(CPUState *cpu)
{
    if (cpu->created && !qemu_cpu_is_self(cpu)) {
        if (atomic_mb_read(&cpu->pending_tlb_flush) != ALL_MMUIDX_BITS) {
            atomic_mb_set(&cpu->pending_tlb_flush, ALL_MMUIDX_BITS);
            async_run_on_cpu(cpu, tlb_flush_global_async_work,
                             RUN_ON_CPU_NULL);
        }
    } else {
        tlb_flush_nocheck(cpu);
    }
}

void tlb_flush_all_cpus(CPUState *src_cpu)
{
    const run_on_cpu_func fn = tlb_flush_global_async_work;
    flush_all_helper(src_cpu, fn, RUN_ON_CPU_NULL);
    fn(src_cpu, RUN_ON_CPU_NULL);
}

void tlb_flush_all_cpus_synced(CPUState *src_cpu)
{
    const run_on_cpu_func fn = tlb_flush_global_async_work;
    flush_all_helper(src_cpu, fn, RUN_ON_CPU_NULL);
    async_safe_run_on_cpu(src_cpu, fn, RUN_ON_CPU_NULL);
}

static void tlb_flush_by_mmuidx_async_work(CPUState *cpu, run_on_cpu_data data)
{
    CPUArchState *env = cpu->env_ptr;
    unsigned long mmu_idx_bitmask = data.host_int;
    int mmu_idx;

    assert_cpu_is_self(cpu);

    tlb_debug("start: mmu_idx:0x%04lx\n", mmu_idx_bitmask);

    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {

        if (test_bit(mmu_idx, &mmu_idx_bitmask)) {
            tlb_debug("%d\n", mmu_idx);

            memset(env->tlb_table[mmu_idx], -1, sizeof(env->tlb_table[0]));
            memset(env->tlb_v_table[mmu_idx], -1, sizeof(env->tlb_v_table[0]));
        }
    }

    cpu_tb_jmp_cache_clear(cpu);

    tlb_debug("done\n");
}

void tlb_flush_by_mmuidx(CPUState *cpu, uint16_t idxmap)
{
    tlb_debug("mmu_idx: 0x%" PRIx16 "\n", idxmap);

    if (!qemu_cpu_is_self(cpu)) {
        uint16_t pending_flushes = idxmap;
        pending_flushes &= ~atomic_mb_read(&cpu->pending_tlb_flush);

        if (pending_flushes) {
            tlb_debug("reduced mmu_idx: 0x%" PRIx16 "\n", pending_flushes);

            atomic_or(&cpu->pending_tlb_flush, pending_flushes);
            async_run_on_cpu(cpu, tlb_flush_by_mmuidx_async_work,
                             RUN_ON_CPU_HOST_INT(pending_flushes));
        }
    } else {
        tlb_flush_by_mmuidx_async_work(cpu,
                                       RUN_ON_CPU_HOST_INT(idxmap));
    }
}

void tlb_flush_by_mmuidx_all_cpus(CPUState *src_cpu, uint16_t idxmap)
{
    const run_on_cpu_func fn = tlb_flush_by_mmuidx_async_work;

    tlb_debug("mmu_idx: 0x%"PRIx16"\n", idxmap);

    flush_all_helper(src_cpu, fn, RUN_ON_CPU_HOST_INT(idxmap));
    fn(src_cpu, RUN_ON_CPU_HOST_INT(idxmap));
}

void tlb_flush_by_mmuidx_all_cpus_synced(CPUState *src_cpu,
                                                       uint16_t idxmap)
{
    const run_on_cpu_func fn = tlb_flush_by_mmuidx_async_work;

    tlb_debug("mmu_idx: 0x%"PRIx16"\n", idxmap);

    flush_all_helper(src_cpu, fn, RUN_ON_CPU_HOST_INT(idxmap));
    async_safe_run_on_cpu(src_cpu, fn, RUN_ON_CPU_HOST_INT(idxmap));
}

static inline bool tlb_hit_page_anyprot(CPUTLBEntry *tlb_entry,
                                        target_ulong page)
{
    return tlb_hit_page(tlb_entry->addr_read, page) ||
           tlb_hit_page(tlb_entry->addr_write, page) ||
           tlb_hit_page(tlb_entry->addr_code, page);
}

static inline void tlb_flush_entry(CPUTLBEntry *tlb_entry, target_ulong page)
{
    if (tlb_hit_page_anyprot(tlb_entry, page)) {
        memset(tlb_entry, -1, sizeof(*tlb_entry));
    }
}

static inline void tlb_flush_vtlb_page(CPUArchState *env, int mmu_idx,
                                       target_ulong page)
{
    int k;
    for (k = 0; k < CPU_VTLB_SIZE; k++) {
        tlb_flush_entry(&env->tlb_v_table[mmu_idx][k], page);
    }
}

static void tlb_flush_page_async_work(CPUState *cpu, run_on_cpu_data data)
{
    CPUArchState *env = cpu->env_ptr;
    target_ulong addr = (target_ulong) data.target_ptr;
    int i;
    int mmu_idx;

    assert_cpu_is_self(cpu);

    tlb_debug("page :" TARGET_FMT_lx "\n", addr);

    /* Check if we need to flush due to large pages.  */
    if ((addr & env->tlb_flush_mask) == env->tlb_flush_addr) {
        tlb_debug("forcing full flush ("
                  TARGET_FMT_lx "/" TARGET_FMT_lx ")\n",
                  env->tlb_flush_addr, env->tlb_flush_mask);

        tlb_flush(cpu);
        return;
    }

    addr &= TARGET_PAGE_MASK;
    i = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        tlb_flush_entry(&env->tlb_table[mmu_idx][i], addr);
        tlb_flush_vtlb_page(env, mmu_idx, addr);
    }

    tb_flush_jmp_cache(cpu, addr);
}

void tlb_flush_page(CPUState *cpu, target_ulong addr)
{
    tlb_debug("page :" TARGET_FMT_lx "\n", addr);

    if (!qemu_cpu_is_self(cpu)) {
        async_run_on_cpu(cpu, tlb_flush_page_async_work,
                         RUN_ON_CPU_TARGET_PTR(addr));
    } else {
        tlb_flush_page_async_work(cpu, RUN_ON_CPU_TARGET_PTR(addr));
    }
}

/* As we are going to hijack the bottom bits of the page address for a
 * mmuidx bit mask we need to fail to build if we can't do that
 */
QEMU_BUILD_BUG_ON(NB_MMU_MODES > TARGET_PAGE_BITS_MIN);

static void tlb_flush_page_by_mmuidx_async_work(CPUState *cpu,
                                                run_on_cpu_data data)
{
    CPUArchState *env = cpu->env_ptr;
    target_ulong addr_and_mmuidx = (target_ulong) data.target_ptr;
    target_ulong addr = addr_and_mmuidx & TARGET_PAGE_MASK;
    unsigned long mmu_idx_bitmap = addr_and_mmuidx & ALL_MMUIDX_BITS;
    int page = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    int mmu_idx;

    assert_cpu_is_self(cpu);

    tlb_debug("page:%d addr:"TARGET_FMT_lx" mmu_idx:0x%lx\n",
              page, addr, mmu_idx_bitmap);

    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        if (test_bit(mmu_idx, &mmu_idx_bitmap)) {
            tlb_flush_entry(&env->tlb_table[mmu_idx][page], addr);
            tlb_flush_vtlb_page(env, mmu_idx, addr);
        }
    }

    tb_flush_jmp_cache(cpu, addr);
}

static void tlb_check_page_and_flush_by_mmuidx_async_work(CPUState *cpu,
                                                          run_on_cpu_data data)
{
    CPUArchState *env = cpu->env_ptr;
    target_ulong addr_and_mmuidx = (target_ulong) data.target_ptr;
    target_ulong addr = addr_and_mmuidx & TARGET_PAGE_MASK;
    unsigned long mmu_idx_bitmap = addr_and_mmuidx & ALL_MMUIDX_BITS;

    tlb_debug("addr:"TARGET_FMT_lx" mmu_idx: %04lx\n", addr, mmu_idx_bitmap);

    /* Check if we need to flush due to large pages.  */
    if ((addr & env->tlb_flush_mask) == env->tlb_flush_addr) {
        tlb_debug("forced full flush ("
                  TARGET_FMT_lx "/" TARGET_FMT_lx ")\n",
                  env->tlb_flush_addr, env->tlb_flush_mask);

        tlb_flush_by_mmuidx_async_work(cpu,
                                       RUN_ON_CPU_HOST_INT(mmu_idx_bitmap));
    } else {
        tlb_flush_page_by_mmuidx_async_work(cpu, data);
    }
}

void tlb_flush_page_by_mmuidx(CPUState *cpu, target_ulong addr, uint16_t idxmap)
{
    target_ulong addr_and_mmu_idx;

    tlb_debug("addr: "TARGET_FMT_lx" mmu_idx:%" PRIx16 "\n", addr, idxmap);

    /* This should already be page aligned */
    addr_and_mmu_idx = addr & TARGET_PAGE_MASK;
    addr_and_mmu_idx |= idxmap;

    if (!qemu_cpu_is_self(cpu)) {
        async_run_on_cpu(cpu, tlb_check_page_and_flush_by_mmuidx_async_work,
                         RUN_ON_CPU_TARGET_PTR(addr_and_mmu_idx));
    } else {
        tlb_check_page_and_flush_by_mmuidx_async_work(
            cpu, RUN_ON_CPU_TARGET_PTR(addr_and_mmu_idx));
    }
}

void tlb_flush_page_by_mmuidx_all_cpus(CPUState *src_cpu, target_ulong addr,
                                       uint16_t idxmap)
{
    const run_on_cpu_func fn = tlb_check_page_and_flush_by_mmuidx_async_work;
    target_ulong addr_and_mmu_idx;

    tlb_debug("addr: "TARGET_FMT_lx" mmu_idx:%"PRIx16"\n", addr, idxmap);

    /* This should already be page aligned */
    addr_and_mmu_idx = addr & TARGET_PAGE_MASK;
    addr_and_mmu_idx |= idxmap;

    flush_all_helper(src_cpu, fn, RUN_ON_CPU_TARGET_PTR(addr_and_mmu_idx));
    fn(src_cpu, RUN_ON_CPU_TARGET_PTR(addr_and_mmu_idx));
}

void tlb_flush_page_by_mmuidx_all_cpus_synced(CPUState *src_cpu,
                                                            target_ulong addr,
                                                            uint16_t idxmap)
{
    const run_on_cpu_func fn = tlb_check_page_and_flush_by_mmuidx_async_work;
    target_ulong addr_and_mmu_idx;

    tlb_debug("addr: "TARGET_FMT_lx" mmu_idx:%"PRIx16"\n", addr, idxmap);

    /* This should already be page aligned */
    addr_and_mmu_idx = addr & TARGET_PAGE_MASK;
    addr_and_mmu_idx |= idxmap;

    flush_all_helper(src_cpu, fn, RUN_ON_CPU_TARGET_PTR(addr_and_mmu_idx));
    async_safe_run_on_cpu(src_cpu, fn, RUN_ON_CPU_TARGET_PTR(addr_and_mmu_idx));
}

void tlb_flush_page_all_cpus(CPUState *src, target_ulong addr)
{
    const run_on_cpu_func fn = tlb_flush_page_async_work;

    flush_all_helper(src, fn, RUN_ON_CPU_TARGET_PTR(addr));
    fn(src, RUN_ON_CPU_TARGET_PTR(addr));
}

void tlb_flush_page_all_cpus_synced(CPUState *src,
                                                  target_ulong addr)
{
    const run_on_cpu_func fn = tlb_flush_page_async_work;

    flush_all_helper(src, fn, RUN_ON_CPU_TARGET_PTR(addr));
    async_safe_run_on_cpu(src, fn, RUN_ON_CPU_TARGET_PTR(addr));
}

/* update the TLBs so that writes to code in the virtual page 'addr'
   can be detected */
void tlb_protect_code(ram_addr_t ram_addr)
{
    cpu_physical_memory_test_and_clear_dirty(ram_addr, TARGET_PAGE_SIZE,
                                             DIRTY_MEMORY_CODE);
}

/* update the TLB so that writes in physical page 'phys_addr' are no longer
   tested for self modifying code */
void tlb_unprotect_code(ram_addr_t ram_addr)
{
    cpu_physical_memory_set_dirty_flag(ram_addr, DIRTY_MEMORY_CODE);
}


/*
 * Dirty write flag handling
 *
 * When the TCG code writes to a location it looks up the address in
 * the TLB and uses that data to compute the final address. If any of
 * the lower bits of the address are set then the slow path is forced.
 * There are a number of reasons to do this but for normal RAM the
 * most usual is detecting writes to code regions which may invalidate
 * generated code.
 *
 * Because we want other vCPUs to respond to changes straight away we
 * update the te->addr_write field atomically. If the TLB entry has
 * been changed by the vCPU in the mean time we skip the update.
 *
 * As this function uses atomic accesses we also need to ensure
 * updates to tlb_entries follow the same access rules. We don't need
 * to worry about this for oversized guests as MTTCG is disabled for
 * them.
 */

static void tlb_reset_dirty_range(CPUTLBEntry *tlb_entry, uintptr_t start,
                           uintptr_t length)
{
#if TCG_OVERSIZED_GUEST
    uintptr_t addr = tlb_entry->addr_write;

    if ((addr & (TLB_INVALID_MASK | TLB_MMIO | TLB_NOTDIRTY)) == 0) {
        addr &= TARGET_PAGE_MASK;
        addr += tlb_entry->addend;
        if ((addr - start) < length) {
            tlb_entry->addr_write |= TLB_NOTDIRTY;
        }
    }
#else
    /* paired with atomic_mb_set in tlb_set_page_with_attrs */
    uintptr_t orig_addr = atomic_mb_read(&tlb_entry->addr_write);
    uintptr_t addr = orig_addr;

    if ((addr & (TLB_INVALID_MASK | TLB_MMIO | TLB_NOTDIRTY)) == 0) {
        addr &= TARGET_PAGE_MASK;
        addr += atomic_read(&tlb_entry->addend);
        if ((addr - start) < length) {
            uintptr_t notdirty_addr = orig_addr | TLB_NOTDIRTY;
            atomic_cmpxchg(&tlb_entry->addr_write, orig_addr, notdirty_addr);
        }
    }
#endif
}

/* For atomic correctness when running MTTCG we need to use the right
 * primitives when copying entries */
static inline void copy_tlb_helper(CPUTLBEntry *d, CPUTLBEntry *s,
                                   bool atomic_set)
{
#if TCG_OVERSIZED_GUEST
    *d = *s;
#else
    if (atomic_set) {
        d->addr_read = s->addr_read;
        d->addr_code = s->addr_code;
        atomic_set(&d->addend, atomic_read(&s->addend));
        /* Pairs with flag setting in tlb_reset_dirty_range */
        atomic_mb_set(&d->addr_write, atomic_read(&s->addr_write));
    } else {
        d->addr_read = s->addr_read;
        d->addr_write = atomic_read(&s->addr_write);
        d->addr_code = s->addr_code;
        d->addend = atomic_read(&s->addend);
    }
#endif
}

/* This is a cross vCPU call (i.e. another vCPU resetting the flags of
 * the target vCPU). As such care needs to be taken that we don't
 * dangerously race with another vCPU update. The only thing actually
 * updated is the target TLB entry ->addr_write flags.
 */
void tlb_reset_dirty(CPUState *cpu, ram_addr_t start1, ram_addr_t length)
{
    CPUArchState *env;

    int mmu_idx;

    env = cpu->env_ptr;
    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        unsigned int i;

        for (i = 0; i < CPU_TLB_SIZE; i++) {
            tlb_reset_dirty_range(&env->tlb_table[mmu_idx][i],
                                  start1, length);
        }

        for (i = 0; i < CPU_VTLB_SIZE; i++) {
            tlb_reset_dirty_range(&env->tlb_v_table[mmu_idx][i],
                                  start1, length);
        }
    }
}

static inline void tlb_set_dirty1(CPUTLBEntry *tlb_entry, target_ulong vaddr)
{
    if (tlb_entry->addr_write == (vaddr | TLB_NOTDIRTY)) {
        tlb_entry->addr_write = vaddr;
    }
}

/* update the TLB corresponding to virtual page vaddr
   so that it is no longer dirty */
void tlb_set_dirty(CPUState *cpu, target_ulong vaddr)
{
    CPUArchState *env = cpu->env_ptr;
    int i;
    int mmu_idx;

    assert_cpu_is_self(cpu);

    vaddr &= TARGET_PAGE_MASK;
    i = (vaddr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        tlb_set_dirty1(&env->tlb_table[mmu_idx][i], vaddr);
    }

    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        int k;
        for (k = 0; k < CPU_VTLB_SIZE; k++) {
            tlb_set_dirty1(&env->tlb_v_table[mmu_idx][k], vaddr);
        }
    }
}

/* Our TLB does not support large pages, so remember the area covered by
   large pages and trigger a full TLB flush if these are invalidated.  */
static void tlb_add_large_page(CPUArchState *env, target_ulong vaddr,
                               target_ulong size)
{
    target_ulong mask = ~(size - 1);

    if (env->tlb_flush_addr == (target_ulong)-1) {
        env->tlb_flush_addr = vaddr & mask;
        env->tlb_flush_mask = mask;
        return;
    }
    /* Extend the existing region to include the new page.
       This is a compromise between unnecessary flushes and the cost
       of maintaining a full variable size TLB.  */
    mask &= env->tlb_flush_mask;
    while (((env->tlb_flush_addr ^ vaddr) & mask) != 0) {
        mask <<= 1;
    }
    env->tlb_flush_addr &= mask;
    env->tlb_flush_mask = mask;
}

/* Add a new TLB entry. At most one entry for a given virtual address
 * is permitted. Only a single TARGET_PAGE_SIZE region is mapped, the
 * supplied size is only used by tlb_flush_page.
 *
 * Called from TCG-generated code, which is under an RCU read-side
 * critical section.
 */
void tlb_set_page_with_attrs(CPUState *cpu, target_ulong vaddr,
                             hwaddr paddr, MemTxAttrs attrs, int prot,
                             int mmu_idx, target_ulong size)
{
    CPUArchState *env = cpu->env_ptr;
    MemoryRegionSection *section;
    unsigned int index;
    target_ulong address;
    target_ulong code_address;
    uintptr_t addend;
    CPUTLBEntry *te, tn;
    hwaddr iotlb, xlat, sz, paddr_page;
    target_ulong vaddr_page;
    int asidx = cpu_asidx_from_attrs(cpu, attrs);

    assert_cpu_is_self(cpu);

    if (size < TARGET_PAGE_SIZE) {
        sz = TARGET_PAGE_SIZE;
    } else {
        if (size > TARGET_PAGE_SIZE) {
            tlb_add_large_page(env, vaddr, size);
        }
        sz = size;
    }
    vaddr_page = vaddr & TARGET_PAGE_MASK;
    paddr_page = paddr & TARGET_PAGE_MASK;

    section = address_space_translate_for_iotlb(cpu, asidx, paddr_page,
                                                &xlat, &sz, attrs, &prot);
    assert(sz >= TARGET_PAGE_SIZE);

    tlb_debug("vaddr=" TARGET_FMT_lx " paddr=0x" TARGET_FMT_plx
              " prot=%x idx=%d\n",
              vaddr, paddr, prot, mmu_idx);

    address = vaddr_page;
    if (size < TARGET_PAGE_SIZE) {
        /*
         * Slow-path the TLB entries; we will repeat the MMU check and TLB
         * fill on every access.
         */
        address |= TLB_RECHECK;
    }
    if (!memory_region_is_ram(section->mr) &&
        !memory_region_is_romd(section->mr)) {
        /* IO memory case */
        address |= TLB_MMIO;
        addend = 0;
    } else {
        /* TLB_MMIO for rom/romd handled below */
        addend = (uintptr_t)memory_region_get_ram_ptr(section->mr) + xlat;
    }

    /* Make sure there's no cached translation for the new page.  */
    tlb_flush_vtlb_page(env, mmu_idx, vaddr_page);

    code_address = address;
    iotlb = memory_region_section_get_iotlb(cpu, section, vaddr_page,
                                            paddr_page, xlat, prot, &address);

    index = (vaddr_page >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    te = &env->tlb_table[mmu_idx][index];

    /*
     * Only evict the old entry to the victim tlb if it's for a
     * different page; otherwise just overwrite the stale data.
     */
    if (!tlb_hit_page_anyprot(te, vaddr_page)) {
        unsigned vidx = env->vtlb_index++ % CPU_VTLB_SIZE;
        CPUTLBEntry *tv = &env->tlb_v_table[mmu_idx][vidx];

        /* Evict the old entry into the victim tlb.  */
        copy_tlb_helper(tv, te, true);
        env->iotlb_v[mmu_idx][vidx] = env->iotlb[mmu_idx][index];
    }

    /* refill the tlb */
    /*
     * At this point iotlb contains a physical section number in the lower
     * TARGET_PAGE_BITS, and either
     *  + the ram_addr_t of the page base of the target RAM (if NOTDIRTY or ROM)
     *  + the offset within section->mr of the page base (otherwise)
     * We subtract the vaddr_page (which is page aligned and thus won't
     * disturb the low bits) to give an offset which can be added to the
     * (non-page-aligned) vaddr of the eventual memory access to get
     * the MemoryRegion offset for the access. Note that the vaddr we
     * subtract here is that of the page base, and not the same as the
     * vaddr we add back in io_readx()/io_writex()/get_page_addr_code().
     */
    env->iotlb[mmu_idx][index].addr = iotlb - vaddr_page;
    env->iotlb[mmu_idx][index].attrs = attrs;

    /* Now calculate the new entry */
    tn.addend = addend - vaddr_page;
    if (prot & PAGE_READ) {
        tn.addr_read = address;
    } else {
        tn.addr_read = -1;
    }

    if (prot & PAGE_EXEC) {
        tn.addr_code = code_address;
    } else {
        tn.addr_code = -1;
    }

    tn.addr_write = -1;
    if (prot & PAGE_WRITE) {
        if ((memory_region_is_ram(section->mr) && section->readonly)
            || memory_region_is_romd(section->mr)) {
            /* Write access calls the I/O callback.  */
            tn.addr_write = address | TLB_MMIO;
        } else if (memory_region_is_ram(section->mr)
                   && cpu_physical_memory_is_clean(
                       memory_region_get_ram_addr(section->mr) + xlat)) {
            tn.addr_write = address | TLB_NOTDIRTY;
        } else {
            tn.addr_write = address;
        }
        if (prot & PAGE_WRITE_INV) {
            tn.addr_write |= TLB_INVALID_MASK;
        }
    }

    /* Pairs with flag setting in tlb_reset_dirty_range */
    copy_tlb_helper(te, &tn, true);
    /* atomic_mb_set(&te->addr_write, write_address); */
}

/* Add a new TLB entry, but without specifying the memory
 * transaction attributes to be used.
 */
void tlb_set_page(CPUState *cpu, target_ulong vaddr,
                  hwaddr paddr, int prot,
                  int mmu_idx, target_ulong size)
{
    tlb_set_page_with_attrs(cpu, vaddr, paddr, MEMTXATTRS_UNSPECIFIED,
                            prot, mmu_idx, size);
}

static void report_bad_exec(CPUState *cpu, target_ulong addr)
{
    /* Accidentally executing outside RAM or ROM is quite common for
     * several user-error situations, so report it in a way that
     * makes it clear that this isn't a QEMU bug and provide suggestions
     * about what a user could do to fix things.
     */
    error_report("Trying to execute code outside RAM or ROM at 0x"
                 TARGET_FMT_lx, addr);
    error_printf("This usually means one of the following happened:\n\n"
                 "(1) You told QEMU to execute a kernel for the wrong machine "
                 "type, and it crashed on startup (eg trying to run a "
                 "raspberry pi kernel on a versatilepb QEMU machine)\n"
                 "(2) You didn't give QEMU a kernel or BIOS filename at all, "
                 "and QEMU executed a ROM full of no-op instructions until "
                 "it fell off the end\n"
                 "(3) Your guest kernel has a bug and crashed by jumping "
                 "off into nowhere\n\n"
                 "This is almost always one of the first two, so check your "
                 "command line and that you are using the right type of kernel "
                 "for this machine.\n"
                 "If you think option (3) is likely then you can try debugging "
                 "your guest with the -d debug options; in particular "
                 "-d guest_errors will cause the log to include a dump of the "
                 "guest register state at this point.\n\n"
                 "Execution cannot continue; stopping here.\n\n");

    /* Report also to the logs, with more detail including register dump */
    qemu_log_mask(LOG_GUEST_ERROR, "qemu: fatal: Trying to execute code "
                  "outside RAM or ROM at 0x" TARGET_FMT_lx "\n", addr);
    log_cpu_state_mask(LOG_GUEST_ERROR, cpu, CPU_DUMP_FPU | CPU_DUMP_CCOP);
}

static inline ram_addr_t qemu_ram_addr_from_host_nofail(void *ptr)
{
    ram_addr_t ram_addr;

    ram_addr = qemu_ram_addr_from_host(ptr);
    if (ram_addr == RAM_ADDR_INVALID) {
        error_report("Bad ram pointer %p", ptr);
        abort();
    }
    return ram_addr;
}

static uint64_t io_readx(CPUArchState *env, CPUIOTLBEntry *iotlbentry,
                         int mmu_idx,
                         target_ulong addr, uintptr_t retaddr,
                         bool recheck, int size)
{
    CPUState *cpu = ENV_GET_CPU(env);
    hwaddr mr_offset;
    MemoryRegionSection *section;
    MemoryRegion *mr;
    uint64_t val;
    bool locked = false;
    MemTxResult r;

    if (recheck) {
        /*
         * This is a TLB_RECHECK access, where the MMU protection
         * covers a smaller range than a target page, and we must
         * repeat the MMU check here. This tlb_fill() call might
         * longjump out if this access should cause a guest exception.
         */
        int index;
        target_ulong tlb_addr;

        tlb_fill(cpu, addr, size, MMU_DATA_LOAD, mmu_idx, retaddr);

        index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
        tlb_addr = env->tlb_table[mmu_idx][index].addr_read;
        if (!(tlb_addr & ~(TARGET_PAGE_MASK | TLB_RECHECK))) {
            /* RAM access */
            uintptr_t haddr = addr + env->tlb_table[mmu_idx][index].addend;

            return ldn_p((void *)haddr, size);
        }
        /* Fall through for handling IO accesses */
    }

    section = iotlb_to_section(cpu, iotlbentry->addr, iotlbentry->attrs);
    mr = section->mr;
    mr_offset = (iotlbentry->addr & TARGET_PAGE_MASK) + addr;

    //printf("-cc-> io_readx: mr_offset: 0x%lx\n", mr_offset);

    cpu->mem_io_pc = retaddr;
    if (mr != &io_mem_rom && mr != &io_mem_notdirty && !cpu->can_do_io) {
        cpu_io_recompile(cpu, retaddr);
    }

    cpu->mem_io_vaddr = addr;

    if (mr->global_locking && !qemu_mutex_iothread_locked()) {
        //qemu_log_mask(LOG_UNIMP, "to read lock\n");
        //work around. dev io always get lock ...
        usleep(20);
        qemu_mutex_lock_iothread();
        locked = true;
        //qemu_log_mask(LOG_UNIMP, "read lock\n");
    }
    r = memory_region_dispatch_read(mr, mr_offset,
                                    &val, size, iotlbentry->attrs);
    if (r != MEMTX_OK) {
        hwaddr physaddr = mr_offset +
            section->offset_within_address_space -
            section->offset_within_region;

        cpu_transaction_failed(cpu, physaddr, addr, size, MMU_DATA_LOAD,
                               mmu_idx, iotlbentry->attrs, r, retaddr);
    }
    if (locked) {
        qemu_mutex_unlock_iothread();
        //qemu_log_mask(LOG_UNIMP, "read unlock\n");
    }

    return val;
}

static void io_writex(CPUArchState *env, CPUIOTLBEntry *iotlbentry,
                      int mmu_idx,
                      uint64_t val, target_ulong addr,
                      uintptr_t retaddr, bool recheck, int size)
{
    CPUState *cpu = ENV_GET_CPU(env);
    hwaddr mr_offset;
    MemoryRegionSection *section;
    MemoryRegion *mr;
    bool locked = false;
    MemTxResult r;

    if (recheck) {
        /*
         * This is a TLB_RECHECK access, where the MMU protection
         * covers a smaller range than a target page, and we must
         * repeat the MMU check here. This tlb_fill() call might
         * longjump out if this access should cause a guest exception.
         */
        int index;
        target_ulong tlb_addr;

        tlb_fill(cpu, addr, size, MMU_DATA_STORE, mmu_idx, retaddr);

        index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
        tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
        if (!(tlb_addr & ~(TARGET_PAGE_MASK | TLB_RECHECK))) {
            /* RAM access */
            uintptr_t haddr = addr + env->tlb_table[mmu_idx][index].addend;

            stn_p((void *)haddr, size, val);
            return;
        }
        /* Fall through for handling IO accesses */
    }

    section = iotlb_to_section(cpu, iotlbentry->addr, iotlbentry->attrs);
    mr = section->mr;
    mr_offset = (iotlbentry->addr & TARGET_PAGE_MASK) + addr;
    if (mr != &io_mem_rom && mr != &io_mem_notdirty && !cpu->can_do_io) {
        cpu_io_recompile(cpu, retaddr);
    }
    cpu->mem_io_vaddr = addr;
    cpu->mem_io_pc = retaddr;

    if (mr->global_locking && !qemu_mutex_iothread_locked()) {
        //work around. dev io always get lock ...
        usleep(20);
        //qemu_log_mask(LOG_UNIMP, "to write lock\n");
        qemu_mutex_lock_iothread();
        //qemu_log_mask(LOG_UNIMP, "write lock\n");
        locked = true;
    }
    r = memory_region_dispatch_write(mr, mr_offset,
                                     val, size, iotlbentry->attrs);
    if (r != MEMTX_OK) {
        hwaddr physaddr = mr_offset +
            section->offset_within_address_space -
            section->offset_within_region;

        cpu_transaction_failed(cpu, physaddr, addr, size, MMU_DATA_STORE,
                               mmu_idx, iotlbentry->attrs, r, retaddr);
    }
    if (locked) {
        qemu_mutex_unlock_iothread();
        //qemu_log_mask(LOG_UNIMP, "write unlock\n");
    }
}

/* Return true if ADDR is present in the victim tlb, and has been copied
   back to the main tlb.  */
static bool victim_tlb_hit(CPUArchState *env, size_t mmu_idx, size_t index,
                           size_t elt_ofs, target_ulong page)
{
    size_t vidx;
    for (vidx = 0; vidx < CPU_VTLB_SIZE; ++vidx) {
        CPUTLBEntry *vtlb = &env->tlb_v_table[mmu_idx][vidx];
        target_ulong cmp = *(target_ulong *)((uintptr_t)vtlb + elt_ofs);

        if (cmp == page) {
            /* Found entry in victim tlb, swap tlb and iotlb.  */
            CPUTLBEntry tmptlb, *tlb = &env->tlb_table[mmu_idx][index];

            copy_tlb_helper(&tmptlb, tlb, false);
            copy_tlb_helper(tlb, vtlb, true);
            copy_tlb_helper(vtlb, &tmptlb, true);

            CPUIOTLBEntry tmpio, *io = &env->iotlb[mmu_idx][index];
            CPUIOTLBEntry *vio = &env->iotlb_v[mmu_idx][vidx];
            tmpio = *io; *io = *vio; *vio = tmpio;
            return true;
        }
    }
    return false;
}

/* Macro to call the above, with local variables from the use context.  */
#define VICTIM_TLB_HIT(TY, ADDR) \
  victim_tlb_hit(env, mmu_idx, index, offsetof(CPUTLBEntry, TY), \
                 (ADDR) & TARGET_PAGE_MASK)

/* NOTE: this function can trigger an exception */
/* NOTE2: the returned address is not exactly the physical address: it
 * is actually a ram_addr_t (in system mode; the user mode emulation
 * version of this function returns a guest virtual address).
 */
tb_page_addr_t get_page_addr_code(CPUArchState *env, target_ulong addr)
{
    int mmu_idx, index;
    void *p;
    MemoryRegion *mr;
    MemoryRegionSection *section;
    CPUState *cpu = ENV_GET_CPU(env);
    CPUIOTLBEntry *iotlbentry;
    hwaddr physaddr, mr_offset;

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = cpu_mmu_index(env, true);
    if (unlikely(!tlb_hit(env->tlb_table[mmu_idx][index].addr_code, addr))) {
        if (!VICTIM_TLB_HIT(addr_code, addr)) {
            tlb_fill(ENV_GET_CPU(env), addr, 0, MMU_INST_FETCH, mmu_idx, 0);
        }
        assert(tlb_hit(env->tlb_table[mmu_idx][index].addr_code, addr));
    }

    if (unlikely(env->tlb_table[mmu_idx][index].addr_code & TLB_RECHECK)) {
        /*
         * This is a TLB_RECHECK access, where the MMU protection
         * covers a smaller range than a target page, and we must
         * repeat the MMU check here. This tlb_fill() call might
         * longjump out if this access should cause a guest exception.
         */
        int index;
        target_ulong tlb_addr;

        tlb_fill(cpu, addr, 0, MMU_INST_FETCH, mmu_idx, 0);

        index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
        tlb_addr = env->tlb_table[mmu_idx][index].addr_code;
        if (!(tlb_addr & ~(TARGET_PAGE_MASK | TLB_RECHECK))) {
            /* RAM access. We can't handle this, so for now just stop */
            cpu_abort(cpu, "Unable to handle guest executing from RAM within "
                      "a small MPU region at 0x" TARGET_FMT_lx, addr);
        }
        /*
         * Fall through to handle IO accesses (which will almost certainly
         * also result in failure)
         */
    }

    iotlbentry = &env->iotlb[mmu_idx][index];
    section = iotlb_to_section(cpu, iotlbentry->addr, iotlbentry->attrs);
    mr = section->mr;
    if (memory_region_is_unassigned(mr)) {
        qemu_mutex_lock_iothread();
        if (memory_region_request_mmio_ptr(mr, addr)) {
            qemu_mutex_unlock_iothread();
            /* A MemoryRegion is potentially added so re-run the
             * get_page_addr_code.
             */
            return get_page_addr_code(env, addr);
        }
        qemu_mutex_unlock_iothread();

        /* Give the new-style cpu_transaction_failed() hook first chance
         * to handle this.
         * This is not the ideal place to detect and generate CPU
         * exceptions for instruction fetch failure (for instance
         * we don't know the length of the access that the CPU would
         * use, and it would be better to go ahead and try the access
         * and use the MemTXResult it produced). However it is the
         * simplest place we have currently available for the check.
         */
        mr_offset = (iotlbentry->addr & TARGET_PAGE_MASK) + addr;
        physaddr = mr_offset +
            section->offset_within_address_space -
            section->offset_within_region;
        cpu_transaction_failed(cpu, physaddr, addr, 0, MMU_INST_FETCH, mmu_idx,
                               iotlbentry->attrs, MEMTX_DECODE_ERROR, 0);

        cpu_unassigned_access(cpu, addr, false, true, 0, 4);
        /* The CPU's unassigned access hook might have longjumped out
         * with an exception. If it didn't (or there was no hook) then
         * we can't proceed further.
         */
        report_bad_exec(cpu, addr);
        exit(1);
    }
    p = (void *)((uintptr_t)addr + env->tlb_table[mmu_idx][index].addend);
    return qemu_ram_addr_from_host_nofail(p);
}

/* Probe for whether the specified guest write access is permitted.
 * If it is not permitted then an exception will be taken in the same
 * way as if this were a real write access (and we will not return).
 * Otherwise the function will return, and there will be a valid
 * entry in the TLB for this access.
 */
void probe_write(CPUArchState *env, target_ulong addr, int size, int mmu_idx,
                 uintptr_t retaddr)
{
    int index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong tlb_addr = env->tlb_table[mmu_idx][index].addr_write;

    if (!tlb_hit(tlb_addr, addr)) {
        /* TLB entry is for a different page */
        if (!VICTIM_TLB_HIT(addr_write, addr)) {
            tlb_fill(ENV_GET_CPU(env), addr, size, MMU_DATA_STORE,
                     mmu_idx, retaddr);
        }
    }
}

/* Probe for a read-modify-write atomic operation.  Do not allow unaligned
 * operations, or io operations to proceed.  Return the host address.  */
static void *atomic_mmu_lookup(CPUArchState *env, target_ulong addr,
                               TCGMemOpIdx oi, uintptr_t retaddr,
                               NotDirtyInfo *ndi)
{
    size_t mmu_idx = get_mmuidx(oi);
    size_t index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    CPUTLBEntry *tlbe = &env->tlb_table[mmu_idx][index];
    target_ulong tlb_addr = tlbe->addr_write;
    TCGMemOp mop = get_memop(oi);
    int a_bits = get_alignment_bits(mop);
    int s_bits = mop & MO_SIZE;
    void *hostaddr;

    /* Adjust the given return address.  */
    retaddr -= GETPC_ADJ;

    /* Enforce guest required alignment.  */
    if (unlikely(a_bits > 0 && (addr & ((1 << a_bits) - 1)))) {
        /* ??? Maybe indicate atomic op to cpu_unaligned_access */
        cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                             mmu_idx, retaddr);
    }

    /* Enforce qemu required alignment.  */
    if (unlikely(addr & ((1 << s_bits) - 1))) {
        /* We get here if guest alignment was not requested,
           or was not enforced by cpu_unaligned_access above.
           We might widen the access and emulate, but for now
           mark an exception and exit the cpu loop.  */
        goto stop_the_world;
    }

    /* Check TLB entry and enforce page permissions.  */
    if (!tlb_hit(tlb_addr, addr)) {
        if (!VICTIM_TLB_HIT(addr_write, addr)) {
            tlb_fill(ENV_GET_CPU(env), addr, 1 << s_bits, MMU_DATA_STORE,
                     mmu_idx, retaddr);
        }
        tlb_addr = tlbe->addr_write & ~TLB_INVALID_MASK;
    }

    /* Notice an IO access or a needs-MMU-lookup access */
    if (unlikely(tlb_addr & (TLB_MMIO | TLB_RECHECK))) {
        /* There's really nothing that can be done to
           support this apart from stop-the-world.  */
        goto stop_the_world;
    }

    /* Let the guest notice RMW on a write-only page.  */
    if (unlikely(tlbe->addr_read != (tlb_addr & ~TLB_NOTDIRTY))) {
        tlb_fill(ENV_GET_CPU(env), addr, 1 << s_bits, MMU_DATA_LOAD,
                 mmu_idx, retaddr);
        /* Since we don't support reads and writes to different addresses,
           and we do have the proper page loaded for write, this shouldn't
           ever return.  But just in case, handle via stop-the-world.  */
        goto stop_the_world;
    }

    hostaddr = (void *)((uintptr_t)addr + tlbe->addend);

    ndi->active = false;
    if (unlikely(tlb_addr & TLB_NOTDIRTY)) {
        ndi->active = true;
        memory_notdirty_write_prepare(ndi, ENV_GET_CPU(env), addr,
                                      qemu_ram_addr_from_host_nofail(hostaddr),
                                      1 << s_bits);
    }

    return hostaddr;

 stop_the_world:
    cpu_loop_exit_atomic(ENV_GET_CPU(env), retaddr);
}

#ifdef TARGET_WORDS_BIGENDIAN
# define TGT_BE(X)  (X)
# define TGT_LE(X)  BSWAP(X)
#else
# define TGT_BE(X)  BSWAP(X)
# define TGT_LE(X)  (X)
#endif

#define MMUSUFFIX _mmu

#define DATA_SIZE 1
#include "softmmu_template.h"

#define DATA_SIZE 2
#include "softmmu_template.h"

#define DATA_SIZE 4
#include "softmmu_template.h"

#define DATA_SIZE 8
#include "softmmu_template.h"

/* First set of helpers allows passing in of OI and RETADDR.  This makes
   them callable from other helpers.  */

#define EXTRA_ARGS     , TCGMemOpIdx oi, uintptr_t retaddr
#define ATOMIC_NAME(X) \
    HELPER(glue(glue(glue(atomic_ ## X, SUFFIX), END), _mmu))
#define ATOMIC_MMU_DECLS NotDirtyInfo ndi
#define ATOMIC_MMU_LOOKUP atomic_mmu_lookup(env, addr, oi, retaddr, &ndi)
#define ATOMIC_MMU_CLEANUP                              \
    do {                                                \
        if (unlikely(ndi.active)) {                     \
            memory_notdirty_write_complete(&ndi);       \
        }                                               \
    } while (0)

#define DATA_SIZE 1
#include "atomic_template.h"

#define DATA_SIZE 2
#include "atomic_template.h"

#define DATA_SIZE 4
#include "atomic_template.h"

#ifdef CONFIG_ATOMIC64
#define DATA_SIZE 8
#include "atomic_template.h"
#endif

#ifdef CONFIG_ATOMIC128
#define DATA_SIZE 16
#include "atomic_template.h"
#endif

/* Second set of helpers are directly callable from TCG as helpers.  */

#undef EXTRA_ARGS
#undef ATOMIC_NAME
#undef ATOMIC_MMU_LOOKUP
#define EXTRA_ARGS         , TCGMemOpIdx oi
#define ATOMIC_NAME(X)     HELPER(glue(glue(atomic_ ## X, SUFFIX), END))
#define ATOMIC_MMU_LOOKUP  atomic_mmu_lookup(env, addr, oi, GETPC(), &ndi)

#define DATA_SIZE 1
#include "atomic_template.h"

#define DATA_SIZE 2
#include "atomic_template.h"

#define DATA_SIZE 4
#include "atomic_template.h"

#ifdef CONFIG_ATOMIC64
#define DATA_SIZE 8
#include "atomic_template.h"
#endif

/* Code access functions.  */

#undef MMUSUFFIX
#define MMUSUFFIX _cmmu
#undef GETPC
#define GETPC() ((uintptr_t)0)
#define SOFTMMU_CODE_ACCESS

#define DATA_SIZE 1
#include "softmmu_template.h"

#define DATA_SIZE 2
#include "softmmu_template.h"

#define DATA_SIZE 4
#include "softmmu_template.h"

#define DATA_SIZE 8
#include "softmmu_template.h"
