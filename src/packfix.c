#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEAP_COMPATIBILITY_INFORMATION 0
#define HEAP_STD 0
#define HEAP_LFH 2
#define MAX_HEAPS 64
#define HEAP_MAGIC_VALUE 0x50414548u
#define OFF_FLAGS 0x70
#define OFF_COMPAT 0x78
#define OFF_GROW 0xb0
#define OFF_MAGIC 0xc0
#define OFF_FREE_LISTS 0x100
#define FREE_LIST_COUNT 61
#define OFF_BINS (OFF_FREE_LISTS + FREE_LIST_COUNT * 32)
#define BIN_STRIDE 48
#define BIN_COUNT 129
#define OFF_SUBHEAP_LIST 0x90
#define SUB_OFF_DATA 24
#define SUB_OFF_ENTRY 32
#define SUB_OFF_USER 48
#define SUB_OFF_BLOCK 56
#define SUB_STRIDE 64
#define ENTRY_LINK 8
#define BLOCK_OFF_FLAGS 7
#define BLOCK_FLAG_FREE 0x01
#define BLOCK_FLAG_FREE_LINK 0x03
#define LINEAR_BITS 2
#define LINEAR_MASK 3
#define HEAP_MIN_LARGE_BLOCK 0xFEFF0
#define MAX_CHAIN 262144
#define MAX_SUBHEAPS 256
#define MAX_QUERIES 384

typedef LONG(WINAPI *pfn_get_process_heaps)(ULONG count, HANDLE *heaps);
typedef LONG(WINAPI *pfn_query_heap_info)(HANDLE heap, ULONG cls, void *info, SIZE_T size_in, SIZE_T *size_out);
typedef LONG(WINAPI *pfn_set_heap_info)(HANDLE heap, ULONG cls, void *info, SIZE_T size);
typedef BOOL(WINAPI *pfn_lock_heap)(HANDLE heap);

typedef struct
{
    unsigned char *lo;
    unsigned char *hi;
} heap_range;

typedef struct
{
    ULONG bucket;
    SIZE_T size;
} chain_node;

typedef struct
{
    SIZE_T want;
    ULONG bin;
    ULONG start;
    ULONG hops;
    ULONG scanned;
    const char *edge;
} size_query;

static pfn_get_process_heaps heap_get_process_heaps;
static pfn_query_heap_info heap_query_info;
static pfn_set_heap_info heap_set_info;
static pfn_lock_heap heap_lock;
static pfn_lock_heap heap_unlock;
static heap_range ranges[MAX_SUBHEAPS];
static ULONG range_count;
static ULONG subheap_capped;
static chain_node chain[MAX_CHAIN];
static ULONG bucket_count[FREE_LIST_COUNT];
static ULONGLONG bucket_sum[FREE_LIST_COUNT];
static SIZE_T bucket_max[FREE_LIST_COUNT];
static ULONG bucket_start[FREE_LIST_COUNT];
static size_query queries[MAX_QUERIES];
static char log_path[MAX_PATH];
static char module_path[MAX_PATH];
static char mode[32];
static DWORD round_delay_ms = 5000;
static DWORD total_window_ms = 300000;

static void log_line(const char *fmt, ...)
{
    FILE *f = fopen(log_path, "a");
    va_list ap;
    if (!f)
        return;
    fprintf(f, "[%10llu] ", (unsigned long long)GetTickCount64());
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static void build_log_path(void)
{
    char env[MAX_PATH];
    char *slash;
    DWORD len = GetEnvironmentVariableA("PACKFIX_LOG", env, sizeof env);

    if (len > 0 && len < sizeof env) {
        snprintf(log_path, sizeof log_path, "%s", env);
        return;
    }
    slash = strrchr(module_path, '\\');
    if (!slash)
        slash = module_path;
    else
        *slash = '\0';
    snprintf(log_path, sizeof log_path, "%s\\packfix.log", module_path);
}

static void pick_mode(void)
{
    char *slash = strrchr(module_path, '\\');

    if (GetEnvironmentVariableA("PACKFIX_MODE", mode, sizeof mode))
        return;
    snprintf(mode, sizeof mode, "report");
    if (slash) {
        if (strstr(slash, "bump"))
            snprintf(mode, sizeof mode, "bump");
        else if (strstr(slash, "pool"))
            snprintf(mode, sizeof mode, "pool");
        else if (strstr(slash, "walk"))
            snprintf(mode, sizeof mode, "walk");
        else if (strstr(slash, "bins"))
            snprintf(mode, sizeof mode, "lfhbins");
        else if (strstr(slash, "lfh"))
            snprintf(mode, sizeof mode, "lfh");
    }
}

static ULONG list_heaps(HANDLE *heaps)
{
    ULONG total;

    if (!heap_get_process_heaps)
        return 0;
    total = (ULONG)heap_get_process_heaps(0, NULL);
    if (total > MAX_HEAPS)
        total = MAX_HEAPS;
    total = (ULONG)heap_get_process_heaps(total, heaps);
    if (total > MAX_HEAPS)
        total = MAX_HEAPS;
    return total;
}

static LONG prev_alloc[MAX_HEAPS][BIN_COUNT];
static LONG prev_freed[MAX_HEAPS][BIN_COUNT];

// Offsets follow struct heap in dlls/ntdll/heap.c for this Wine build; the magic word validates them.
static void probe_heap(const char *tag, HANDLE heap, ULONG slot, int absolute)
{
    unsigned char *base = (unsigned char *)heap;
    unsigned char *bins = *(unsigned char **)(base + OFF_BINS);
    ULONG magic = *(ULONG *)(base + OFF_MAGIC);
    ULONG flags = *(ULONG *)(base + OFF_FLAGS);
    ULONG compat = *(ULONG *)(base + OFF_COMPAT);
    SIZE_T grow = *(SIZE_T *)(base + OFF_GROW);
    ULONG i;

    log_line("%s probe heap=%p magic=%08lx flags=%08lx growable=%d compat=%lu grow=%llu bins=%p",
             tag, heap, magic, flags, (flags & HEAP_GROWABLE) != 0, compat, (unsigned long long)grow, (void *)bins);
    if (magic != HEAP_MAGIC_VALUE)
        return;
    if (!bins) {
        log_line("%s bins=NULL", tag);
        return;
    }
    for (i = 0; i < BIN_COUNT; i++) {
        unsigned char *bin = bins + (SIZE_T)i * BIN_STRIDE;
        LONG alloc = *(LONG *)(bin + 0);
        LONG freed = *(LONG *)(bin + 4);
        LONG enabled = *(LONG *)(bin + 8);
        if (absolute ? (alloc || freed || enabled)
                     : (alloc != prev_alloc[slot][i] || freed != prev_freed[slot][i]))
            log_line("%s bin %3u alloc=%ld freed=%ld enabled=%ld", tag, i, alloc, freed, enabled);
        prev_alloc[slot][i] = alloc;
        prev_freed[slot][i] = freed;
    }
}

static SIZE_T free_list_lower(ULONG index)
{
    ULONG log = index >> LINEAR_BITS, linear = index & LINEAR_MASK;

    if (log == 0)
        return (SIZE_T)index * 16;
    return ((SIZE_T)(4 + linear) << (log - 1)) * 16;
}

static ULONG free_list_index(SIZE_T size)
{
    SIZE_T v = size / 16;
    ULONG bit = 0, index;

    if (v == 0)
        return 0;
    while (v >> bit)
        bit++;
    bit--;
    if (bit < LINEAR_BITS)
        index = (ULONG)v;
    else
        index = (bit - 1) * 4 + (ULONG)((v >> (bit - LINEAR_BITS)) & LINEAR_MASK);
    return index >= FREE_LIST_COUNT ? FREE_LIST_COUNT - 1 : index;
}

static SIZE_T block_bin_size(ULONG bin)
{
    static const SIZE_T mins[8] = {0, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000};
    ULONG group = bin >> 4;
    SIZE_T step = group ? mins[group] >> 4 : 16;

    if (bin >= 0x80)
        return HEAP_MIN_LARGE_BLOCK - 1;
    return mins[group] + (bin - group * 16 + 1) * step;
}

static int in_known_range(const unsigned char *p)
{
    ULONG i;

    for (i = 0; i < range_count; i++)
        if (p >= ranges[i].lo && p + 8 <= ranges[i].hi)
            return 1;
    return 0;
}

static void collect_subheaps(unsigned char *base)
{
    unsigned char *head = base + OFF_SUBHEAP_LIST;
    unsigned char *ptr = *(unsigned char **)(head + 8);
    ULONG guard = 0;

    range_count = 0;
    subheap_capped = 0;
    while (ptr && ptr != head && guard < MAX_SUBHEAPS)
    {
        unsigned char *sub = ptr - SUB_OFF_ENTRY;
        SIZE_T data = *(SIZE_T *)(sub + SUB_OFF_DATA);

        if (*(unsigned char **)(sub + SUB_OFF_USER) == base && data < 0x40000000)
        {
            ranges[range_count].lo = sub + SUB_OFF_BLOCK;
            ranges[range_count].hi = sub + SUB_STRIDE + data;
            range_count++;
        }
        ptr = *(unsigned char **)(ptr + 8);
        guard++;
    }
    if (ptr && ptr != head)
        subheap_capped = 1;
}

static void walk_heap(const char *tag, HANDLE heap)
{
    unsigned char *base = (unsigned char *)heap;
    unsigned char *sent = base + OFF_FREE_LISTS;
    unsigned char *head = sent + ENTRY_LINK;
    unsigned char *ptr = *(unsigned char **)head;
    ULONG bucket = 0, hops = 0, bad = 0, n = 0, truncated = 0, i, j, q, qcount = 0, b;
    ULONGLONG total = 0;

    if (*(ULONG *)(base + OFF_MAGIC) != HEAP_MAGIC_VALUE)
        return;
    if (!heap_lock || !heap_unlock)
    {
        log_line("%s lock api missing", tag);
        return;
    }
    if (!heap_lock(heap))
    {
        log_line("%s RtlLockHeap failed heap=%p", tag, heap);
        return;
    }
    collect_subheaps(base);
    truncated = subheap_capped;
    memset(bucket_count, 0, sizeof bucket_count);
    memset(bucket_sum, 0, sizeof bucket_sum);
    memset(bucket_max, 0, sizeof bucket_max);

    while (ptr && ptr != head && hops < MAX_CHAIN)
    {
        unsigned char *node = ptr - ENTRY_LINK;
        ULONG flags;

        if (node >= sent && node < sent + FREE_LIST_COUNT * 32 && (node - sent) % 32 == 0)
        {
            bucket = (ULONG)(node - sent) / 32;
        }
        else if (!in_known_range(node))
        {
            bad++;
            break;
        }
        else
        {
            flags = node[BLOCK_OFF_FLAGS];
            if (flags == BLOCK_FLAG_FREE_LINK)
                bad++;
            else if (flags & BLOCK_FLAG_FREE)
            {
                SIZE_T size = ((SIZE_T)*(USHORT *)(node + 2) << 16) + *(USHORT *)node;
                size *= 16;
                if (size >= 16 && size <= 0x40000000)
                {
                    if (n < MAX_CHAIN)
                    {
                        chain[n].bucket = bucket;
                        chain[n].size = size;
                        n++;
                    }
                    else
                        truncated = 1;
                    bucket_count[bucket]++;
                    bucket_sum[bucket] += size;
                    if (size > bucket_max[bucket])
                        bucket_max[bucket] = size;
                    total += size;
                }
                else
                    bad++;
            }
            else
                bad++;
        }
        ptr = *(unsigned char **)ptr;
        hops++;
    }
    if (hops >= MAX_CHAIN)
        truncated = 1;
    heap_unlock(heap);

    log_line("%s heap=%p subheaps=%u free_nodes=%u free_bytes=%llu bad=%u truncated=%u",
             tag, heap, range_count, n, total, bad, truncated);
    for (i = 0; i < FREE_LIST_COUNT; i++)
        if (bucket_count[i])
            log_line("%s heap=%p bkt=%3u n=%u sum=%llu max=%llu",
                     tag, heap, i, bucket_count[i], bucket_sum[i], bucket_max[i]);
    for (i = 0; i < FREE_LIST_COUNT; i++)
    {
        SIZE_T want = (i + 1 < FREE_LIST_COUNT) ? free_list_lower(i + 1) - 16 : HEAP_MIN_LARGE_BLOCK - 17;
        ULONG start = free_list_index(want);

        if (want < free_list_lower(i) || want >= HEAP_MIN_LARGE_BLOCK || start != i)
            continue;
        if (qcount < MAX_QUERIES)
        {
            queries[qcount].bin = 0x80;
            queries[qcount].edge = "bkt";
            queries[qcount].want = want;
            queries[qcount].start = start;
            qcount++;
        }
    }
    {
        unsigned char *bins = *(unsigned char **)(base + OFF_BINS);

        for (i = 1; i < 0x80 && qcount + 2 <= MAX_QUERIES; i++)
        {
            SIZE_T lo, hi;
            LONG alloc = 1, enabled = 0;

            if (bins)
            {
                alloc = *(LONG *)(bins + (SIZE_T)i * BIN_STRIDE);
                enabled = *(LONG *)(bins + (SIZE_T)i * BIN_STRIDE + 8);
            }
            if (enabled || !alloc)
                continue;
            lo = block_bin_size(i - 1) + 1;
            hi = block_bin_size(i);
            if (hi > HEAP_MIN_LARGE_BLOCK - 17)
                hi = HEAP_MIN_LARGE_BLOCK - 17;
            if (lo > hi)
                lo = hi;
            queries[qcount].bin = i;
            queries[qcount].edge = "lo";
            queries[qcount].want = lo;
            queries[qcount].start = free_list_index(lo);
            qcount++;
            queries[qcount].bin = i;
            queries[qcount].edge = "hi";
            queries[qcount].want = hi;
            queries[qcount].start = free_list_index(hi);
            qcount++;
        }
    }

    {
        j = 0;
        for (b = 0; b < FREE_LIST_COUNT; b++)
        {
            while (j < n && chain[j].bucket < b)
                j++;
            bucket_start[b] = j;
        }
    }

    for (q = 0; q < qcount; q++)
    {
        ULONG seen = 0;

        queries[q].hops = 0;
        for (j = queries[q].start; j < n; j++)
        {
            seen++;
            if (chain[j].size >= queries[q].want)
            {
                queries[q].hops = seen;
                break;
            }
        }
        queries[q].scanned = seen;
    }

    for (q = 0; q < qcount; q++)
    {
        if (queries[q].bin == 0x80)
            log_line("%s heap=%p fitq bkt=%3u want=%llu hops=%u scanned=%u found=%u",
                     tag, heap, queries[q].start, (unsigned long long)queries[q].want,
                     queries[q].hops, queries[q].scanned, queries[q].hops != 0);
        else
            log_line("%s heap=%p binq bin=%3u edge=%s want=%llu hops=%u scanned=%u found=%u",
                     tag, heap, queries[q].bin, queries[q].edge, (unsigned long long)queries[q].want,
                     queries[q].hops, queries[q].scanned, queries[q].hops != 0);
    }
}

static void report_heaps(const char *tag, int absolute)
{
    HANDLE heaps[MAX_HEAPS];
    ULONG total = list_heaps(heaps);
    ULONG i;

    log_line("%s heaps=%u", tag, total);
    for (i = 0; i < total; i++) {
        ULONG compat = 0;
        LONG status = 0xC0000001L;
        if (heap_query_info)
            status = heap_query_info(heaps[i], HEAP_COMPATIBILITY_INFORMATION, &compat, sizeof compat, NULL);
        log_line("%s heap[%u]=%p compat=%u status=%08lx", tag, i, heaps[i], compat, (unsigned long)status);
        probe_heap(tag, heaps[i], i, absolute);
    }
}

static void walk_heaps(const char *tag)
{
    HANDLE heaps[MAX_HEAPS];
    ULONG total = list_heaps(heaps);
    ULONG i;

    for (i = 0; i < total; i++)
        walk_heap(tag, heaps[i]);
}

static void enable_lfh(const char *tag)
{
    HANDLE heaps[MAX_HEAPS];
    ULONG total = list_heaps(heaps);
    ULONG i;

    for (i = 0; i < total; i++) {
        ULONG info = HEAP_LFH;
        ULONG compat = 0;
        LONG status = 0xC0000001L;
        if (heap_set_info)
            status = heap_set_info(heaps[i], HEAP_COMPATIBILITY_INFORMATION, &info, sizeof info);
        if (heap_query_info)
            heap_query_info(heaps[i], HEAP_COMPATIBILITY_INFORMATION, &compat, sizeof compat, NULL);
        log_line("%s heap[%u]=%p set_status=%08lx compat=%u", tag, i, heaps[i], (unsigned long)status, compat);
    }
}

static void enable_bins(const char *tag)
{
    HANDLE heaps[MAX_HEAPS];
    ULONG total = list_heaps(heaps);
    ULONG i;

    for (i = 0; i < total; i++) {
        unsigned char *base = (unsigned char *)heaps[i];
        unsigned char *bins = *(unsigned char **)(base + OFF_BINS);
        ULONG magic = *(ULONG *)(base + OFF_MAGIC);
        ULONG compat = 0;
        ULONG j, changed = 0;

        if (magic != HEAP_MAGIC_VALUE || !bins) {
            log_line("%s heap=%p bins unavailable magic=%08lx", tag, heaps[i], magic);
            continue;
        }
        if (heap_query_info)
            heap_query_info(heaps[i], HEAP_COMPATIBILITY_INFORMATION, &compat, sizeof compat, NULL);
        if (compat != HEAP_LFH) {
            log_line("%s heap=%p compat=%u not HEAP_LFH, skip", tag, heaps[i], compat);
            continue;
        }
        for (j = 1; j < 0x80; j++) {
            LONG *count_alloc = (LONG *)(bins + (SIZE_T)j * BIN_STRIDE);
            LONG *enabled = (LONG *)(bins + (SIZE_T)j * BIN_STRIDE + 8);
            if (*count_alloc <= 0 || *enabled)
                continue;
            InterlockedExchange(enabled, 1);
            changed++;
        }
        log_line("%s heap=%p compat=%u bins_turned_on=%lu", tag, heaps[i], compat, changed);
    }
}

#define CLASS_SLOTS 1024
#define CLASS_MASK (CLASS_SLOTS - 1)
#define LEARN_SLOTS 1024
#define LEARN_MASK (LEARN_SLOTS - 1)
#define PROV_SLOTS 65536
#define PROV_MASK (PROV_SLOTS - 1)
#define PROV_IN_USE 1
#define PROV_IN_CACHE 2
#define CLASS_SIZE_MAX 0x4000
#define CLASS_BYTES_MAX ((SIZE_T)48 << 20)
#define HASH_MUL 0x9e3779b97f4a7c15ULL
#define PROBE_LIMIT 24

typedef void *(WINAPI *pfn_alloc)(HANDLE, ULONG, SIZE_T);
typedef BOOL (WINAPI *pfn_free)(HANDLE, ULONG, void *);
typedef SIZE_T (WINAPI *pfn_size)(HANDLE, ULONG, void *);

typedef struct {
    SIZE_T usable;
    void *head;
    LONG count;
    LONG cap;
} size_class;

typedef struct {
    HANDLE heap;
    SIZE_T size;
    SIZE_T usable;
} learned_entry;

typedef struct {
    void *ptr;
    SIZE_T usable;
    LONG state;
} provenance;

static size_class classes[CLASS_SLOTS];
static learned_entry learns[LEARN_SLOTS];
static provenance provs[PROV_SLOTS];
static SRWLOCK pool_gate = SRWLOCK_INIT;
static DWORD gate_tid;
static pfn_alloc orig_alloc;
static pfn_free orig_free;
static pfn_size heap_size;
static LONG pool_on;
static LONG pool_hits;
static LONG pool_misses;
static LONG pool_absorbs;
static LONG pool_dup_free;
static LONG pool_untracked;
static LONG pool_pass_free;
static LONG pool_learn_fail;
static LONG pool_class_fail;
static LONG pool_cached;
static LONG64 pool_bytes;
static unsigned char *patched_alloc;
static unsigned char *patched_free;

static ULONG hash_slot(SIZE_T v, ULONG mask)
{
    v *= HASH_MUL;
    return (ULONG)((v >> 32) & mask);
}

static size_class *class_find(SIZE_T usable)
{
    ULONG i = hash_slot(usable >> 4, CLASS_MASK);
    ULONG probes;
    for (probes = 0; probes < PROBE_LIMIT; probes++, i = (i + 1) & CLASS_MASK) {
        if (classes[i].usable == usable)
            return &classes[i];
        if (!classes[i].usable)
            return NULL;
    }
    return NULL;
}

static size_class *class_add(SIZE_T usable)
{
    ULONG i = hash_slot(usable >> 4, CLASS_MASK);
    ULONG probes;
    for (probes = 0; probes < PROBE_LIMIT; probes++, i = (i + 1) & CLASS_MASK) {
        if (!classes[i].usable) {
            classes[i].usable = usable;
            classes[i].count = 0;
            classes[i].head = NULL;
            classes[i].cap = usable <= 0x1000 ? 2048 : 256;
            return &classes[i];
        }
        if (classes[i].usable == usable)
            return &classes[i];
    }
    InterlockedIncrement(&pool_class_fail);
    return NULL;
}

static void class_push(size_class *cls, void *block)
{
    *(void **)block = cls->head;
    cls->head = block;
    cls->count++;
    pool_cached++;
    pool_bytes += (LONG64)cls->usable;
}

static void *class_pop(size_class *cls)
{
    void *block = cls->head;
    if (!block)
        return NULL;
    cls->head = *(void **)block;
    cls->count--;
    pool_cached--;
    pool_bytes -= (LONG64)cls->usable;
    return block;
}

static learned_entry *learn_find(HANDLE heap, SIZE_T size)
{
    ULONG i = hash_slot((SIZE_T)heap ^ (size * HASH_MUL), LEARN_MASK);
    ULONG probes;
    for (probes = 0; probes < PROBE_LIMIT; probes++, i = (i + 1) & LEARN_MASK) {
        if (learns[i].size == size && learns[i].heap == heap)
            return &learns[i];
        if (!learns[i].size)
            return NULL;
    }
    return NULL;
}

static learned_entry *learn_add(HANDLE heap, SIZE_T size, SIZE_T usable)
{
    ULONG i = hash_slot((SIZE_T)heap ^ (size * HASH_MUL), LEARN_MASK);
    ULONG probes;
    for (probes = 0; probes < PROBE_LIMIT; probes++, i = (i + 1) & LEARN_MASK) {
        if (!learns[i].size) {
            learns[i].heap = heap;
            learns[i].size = size;
            learns[i].usable = usable;
            return &learns[i];
        }
        if (learns[i].size == size && learns[i].heap == heap)
            return &learns[i];
    }
    InterlockedIncrement(&pool_learn_fail);
    return NULL;
}

static provenance *prov_find(void *ptr)
{
    ULONG i = hash_slot((SIZE_T)ptr >> 4, PROV_MASK);
    ULONG probes;
    for (probes = 0; probes < PROBE_LIMIT; probes++, i = (i + 1) & PROV_MASK) {
        if (provs[i].ptr == ptr)
            return &provs[i];
        if (!provs[i].ptr)
            return NULL;
    }
    return NULL;
}

static provenance *prov_add(void *ptr, SIZE_T usable, LONG state)
{
    ULONG i = hash_slot((SIZE_T)ptr >> 4, PROV_MASK);
    ULONG probes;
    for (probes = 0; probes < PROBE_LIMIT; probes++, i = (i + 1) & PROV_MASK) {
        if (!provs[i].ptr || provs[i].ptr == ptr) {
            provs[i].ptr = ptr;
            provs[i].usable = usable;
            provs[i].state = state;
            return &provs[i];
        }
    }
    return NULL;
}

static int gate_enter(void)
{
    DWORD tid = GetCurrentThreadId();

    if (gate_tid == tid)
        return 0;
    AcquireSRWLockExclusive(&pool_gate);
    gate_tid = tid;
    return 1;
}

static void gate_leave(void)
{
    gate_tid = 0;
    ReleaseSRWLockExclusive(&pool_gate);
}

static void *WINAPI hook_alloc(HANDLE heap, ULONG flags, SIZE_T size)
{
    size_class *cls = NULL;
    void *block = NULL;

    if (!pool_on || !size || size > CLASS_SIZE_MAX ||
        (flags & ~(HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS)))
        return orig_alloc(heap, flags, size);

    if (gate_enter()) {
        learned_entry *l = learn_find(heap, size);
        if (l) {
            cls = class_find(l->usable);
            if (cls)
                block = class_pop(cls);
            if (block)
                prov_add(block, cls->usable, PROV_IN_USE);
        }
        gate_leave();
    }

    if (block) {
        if (flags & HEAP_ZERO_MEMORY)
            memset(block, 0, cls->usable);
        InterlockedIncrement(&pool_hits);
        return block;
    }

    {
        void *ptr = orig_alloc(heap, flags, size);
        SIZE_T usable;
        if (!ptr)
            return NULL;
        InterlockedIncrement(&pool_misses);
        usable = heap_size(heap, 0, ptr);
        if (usable == 0 || usable == (SIZE_T)-1 || usable > CLASS_SIZE_MAX)
            return ptr;
        if (gate_enter()) {
            learn_add(heap, size, usable);
            if (class_add(usable))
                prov_add(ptr, usable, PROV_IN_USE);
            gate_leave();
        }
        return ptr;
    }
}

static int pool_take(HANDLE heap, void *ptr)
{
    provenance *p;
    SIZE_T usable;
    size_class *cls = NULL;
    int taken = 0;

    if (!gate_enter())
        return 0;
    p = prov_find(ptr);
    if (!p) {
        InterlockedIncrement(&pool_untracked);
    } else if (p->state == PROV_IN_CACHE) {
        InterlockedIncrement(&pool_dup_free);
    } else {
        usable = heap_size(heap, 0, ptr);
        if (usable == p->usable && !(((char *)ptr)[-1] & BLOCK_FLAG_FREE) &&
            pool_bytes + (LONG64)usable <= (LONG64)CLASS_BYTES_MAX) {
            cls = class_find(usable);
            if (cls && cls->count < cls->cap) {
                p->state = PROV_IN_CACHE;
                class_push(cls, ptr);
                InterlockedIncrement(&pool_absorbs);
                taken = 1;
            }
        }
        if (!taken) {
            p->state = 0;
            p->ptr = NULL;
            InterlockedIncrement(&pool_pass_free);
        }
    }
    gate_leave();
    return taken;
}

static BOOL WINAPI hook_free(HANDLE heap, ULONG flags, void *ptr)
{
    if (!pool_on || !ptr)
        return orig_free(heap, flags, ptr);
    if (pool_take(heap, ptr))
        return TRUE;
    return orig_free(heap, flags, ptr);
}

static void pool_stats(const char *tag)
{
    log_line("%s hits=%d misses=%d absorbs=%d pass_free=%d untracked=%d dup_free=%d learn_fail=%d class_fail=%d cached=%d bytes=%lld on=%d",
             tag, pool_hits, pool_misses, pool_absorbs, pool_pass_free, pool_untracked, pool_dup_free, pool_learn_fail, pool_class_fail,
             pool_cached, (long long)pool_bytes, pool_on);
}

static int padding_ok(const unsigned char *entry)
{
    static const unsigned char pad[8] = {0x48, 0x8d, 0xa4, 0x24, 0x00, 0x00, 0x00, 0x00};
    unsigned char got[8];
    ULONG i;
    for (i = 0; i < 8; i++)
        got[i] = entry[i];
    return memcmp(got, pad, 8) == 0;
}

static unsigned char *near_page(unsigned char *entry)
{
    static const LONG steps[] = {0x10000, -0x10000, 0x100000, -0x100000, 0x400000, -0x400000};
    ULONG i;
    for (i = 0; i < sizeof steps / sizeof steps[0]; i++) {
        unsigned char *cand = (unsigned char *)(((SIZE_T)entry + (SIZE_T)(LONG64)steps[i]) & ~(SIZE_T)0xffff);
        void *got = VirtualAlloc(cand, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (got)
            return (unsigned char *)got;
    }
    return NULL;
}

static int patch_entry(unsigned char *entry, void *hook, const char *tag)
{
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *target = (unsigned char *)hook;
    unsigned char tramp[12];
    unsigned char patch[8];
    LONG64 old;
    LONG64 value;
    DWORD old_prot;
    LONG64 rel;

    if (!VirtualQuery(entry, &mbi, sizeof mbi)) {
        log_line("patch %s VirtualQuery failed", tag);
        return 0;
    }
    rel = (LONG64)((SIZE_T)target - (SIZE_T)entry) - 5;
    if (rel > 0x7ffffff0LL || rel < -0x7ffffff0LL) {
        unsigned char *page = near_page(entry);
        if (!page) {
            log_line("patch %s too far, no near page", tag);
            return 0;
        }
        tramp[0] = 0x48;
        tramp[1] = 0xb8;
        memcpy(tramp + 2, &target, 8);
        tramp[10] = 0xff;
        tramp[11] = 0xe0;
        memcpy(page, tramp, sizeof tramp);
        FlushInstructionCache(GetCurrentProcess(), page, sizeof tramp);
        target = page;
        rel = (LONG64)((SIZE_T)target - (SIZE_T)entry) - 5;
        if (rel > 0x7ffffff0LL || rel < -0x7ffffff0LL) {
            log_line("patch %s near page still too far", tag);
            return 0;
        }
    }
    if (!VirtualProtect(entry, 8, PAGE_EXECUTE_READWRITE, &old_prot)) {
        log_line("patch %s VirtualProtect failed prot=%08lx", tag, mbi.Protect);
        return 0;
    }
    patch[0] = 0xe9;
    patch[1] = (unsigned char)(rel & 0xff);
    patch[2] = (unsigned char)((rel >> 8) & 0xff);
    patch[3] = (unsigned char)((rel >> 16) & 0xff);
    patch[4] = (unsigned char)((rel >> 24) & 0xff);
    patch[5] = 0x90;
    patch[6] = 0x90;
    patch[7] = 0x90;
    memcpy(&value, patch, 8);
    old = InterlockedExchange64((volatile LONG64 *)entry, value);
    VirtualProtect(entry, 8, old_prot & ~(DWORD)PAGE_GUARD, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), entry, 8);
    (void)old;
    log_line("patch %s entry=%p target=%p rel=%lld prot=%08lx", tag, entry, target, (long long)rel, mbi.Protect);
    return 1;
}

static void install_hooks(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    unsigned char *ea;
    unsigned char *ef;

    if (!ntdll) {
        log_line("pool abort: ntdll not found");
        return;
    }
    ea = (unsigned char *)GetProcAddress(ntdll, "RtlAllocateHeap");
    ef = (unsigned char *)GetProcAddress(ntdll, "RtlFreeHeap");
    heap_size = (pfn_size)GetProcAddress(ntdll, "RtlSizeHeap");
    if (!ea || !ef || !heap_size) {
        log_line("pool abort: exports alloc=%p free=%p size=%p", ea, ef, (void *)heap_size);
        return;
    }
    if (!padding_ok(ea) || !padding_ok(ef)) {
        log_line("pool abort: padding alloc=%p free=%p", ea, ef);
        return;
    }
    if (((SIZE_T)ea & 7) || ((SIZE_T)ef & 7)) {
        log_line("pool abort: entry alignment alloc=%p free=%p", ea, ef);
        return;
    }
    orig_alloc = (pfn_alloc)(ea + 8);
    orig_free = (pfn_free)(ef + 8);
    log_line("pool init alloc_entry=%p free_entry=%p orig_alloc=%p orig_free=%p size=%p",
             ea, ef, (void *)orig_alloc, (void *)orig_free, (void *)heap_size);
    if (!patch_entry(ef, (void *)hook_free, "free"))
        return;
    patched_free = ef;
    if (!patch_entry(ea, (void *)hook_alloc, "alloc"))
        return;
    patched_alloc = ea;
    pool_on = 1;
}

static void remove_hooks(void)
{
    LONG64 restore = 0x0000000024a48d48LL;
    DWORD prot;

    pool_on = 0;
    if (patched_alloc) {
        if (VirtualProtect(patched_alloc, 8, PAGE_EXECUTE_READWRITE, &prot)) {
            InterlockedExchange64((volatile LONG64 *)patched_alloc, restore);
            VirtualProtect(patched_alloc, 8, prot & ~(DWORD)PAGE_GUARD, &prot);
            FlushInstructionCache(GetCurrentProcess(), patched_alloc, 8);
        }
    }
    if (patched_free) {
        if (VirtualProtect(patched_free, 8, PAGE_EXECUTE_READWRITE, &prot)) {
            InterlockedExchange64((volatile LONG64 *)patched_free, restore);
            VirtualProtect(patched_free, 8, prot & ~(DWORD)PAGE_GUARD, &prot);
            FlushInstructionCache(GetCurrentProcess(), patched_free, 8);
        }
    }
    log_line("pool hooks removed");
}

#define BUMP_MIN_BLOCK 0x400
#define BUMP_MAX_DELTA 0x1000
#define BUMP_MAX_SITES 8
#define SIG_MAX 64

typedef LONG (*pfn_allocate_block)(void *heap, ULONG flags, SIZE_T block_size, SIZE_T size, void **ret);

static const char free_list_loop_sig[] = "0F B6 53 FF 80 FA 03 74 ?? 83 E2 01 0F B7 43 F8 74";

static pfn_allocate_block orig_allocate_block;
static unsigned char *bump_sites[BUMP_MAX_SITES];
static LONG bump_count;

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 0;
}

static ULONG parse_sig(const char *sig, unsigned char *bytes, unsigned char *mask)
{
    ULONG n = 0;

    while (*sig && n < SIG_MAX) {
        if (*sig == ' ') {
            sig++;
        } else if (*sig == '?') {
            bytes[n] = 0;
            mask[n++] = 0;
            sig += sig[1] == '?' ? 2 : 1;
        } else {
            bytes[n] = (unsigned char)(hex_digit(sig[0]) << 4 | hex_digit(sig[1]));
            mask[n++] = 1;
            sig += 2;
        }
    }
    return n;
}

static IMAGE_SECTION_HEADER *exec_section(unsigned char *base, WORD index)
{
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt) + index;

    if (index >= nt->FileHeader.NumberOfSections || !(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
        return NULL;
    return sec;
}

static unsigned char *find_unique_sig(unsigned char *base, const char *sig, ULONG *matches)
{
    unsigned char bytes[SIG_MAX], mask[SIG_MAX];
    ULONG n = parse_sig(sig, bytes, mask);
    WORD count = ((IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew))->FileHeader.NumberOfSections;
    unsigned char *found = NULL;
    WORD s;

    *matches = 0;
    for (s = 0; s < count; s++) {
        IMAGE_SECTION_HEADER *sec = exec_section(base, s);
        unsigned char *lo, *p;
        if (!sec)
            continue;
        lo = base + sec->VirtualAddress;
        for (p = lo; p + n <= lo + sec->Misc.VirtualSize; p++) {
            ULONG j = 0;
            while (j < n && (!mask[j] || p[j] == bytes[j]))
                j++;
            if (j == n) {
                (*matches)++;
                found = p;
            }
        }
    }
    return *matches == 1 ? found : NULL;
}

static ULONG find_call_sites(unsigned char *base, unsigned char *target, unsigned char **sites)
{
    WORD count = ((IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew))->FileHeader.NumberOfSections;
    ULONG found = 0;
    WORD s;

    for (s = 0; s < count; s++) {
        IMAGE_SECTION_HEADER *sec = exec_section(base, s);
        unsigned char *lo, *p;
        LONG rel;
        if (!sec)
            continue;
        lo = base + sec->VirtualAddress;
        for (p = lo; p + 5 <= lo + sec->Misc.VirtualSize && found < BUMP_MAX_SITES; p++) {
            if (*p != 0xe8)
                continue;
            memcpy(&rel, p + 1, 4);
            if (p + 5 + rel == target)
                sites[found++] = p;
        }
    }
    return found;
}

static SIZE_T bumped_block(SIZE_T block)
{
    SIZE_T lower, upper;
    ULONG index;

    if (block <= BUMP_MIN_BLOCK || block >= HEAP_MIN_LARGE_BLOCK)
        return block;
    index = free_list_index(block);
    if (index >= FREE_LIST_COUNT - 2)
        return block;
    lower = free_list_lower(index);
    upper = free_list_lower(index + 1);
    if (block - lower < (upper - lower) / 2 || upper - block > BUMP_MAX_DELTA || upper >= HEAP_MIN_LARGE_BLOCK)
        return block;
    return upper;
}

static LONG hook_allocate_block(void *heap, ULONG flags, SIZE_T block_size, SIZE_T size, void **ret)
{
    SIZE_T want = bumped_block(block_size);

    if (want != block_size)
        InterlockedIncrement(&bump_count);
    return orig_allocate_block(heap, flags, want, size, ret);
}

static int rewrite_call(unsigned char *site, unsigned char *expect, unsigned char *target)
{
    LONG64 *chunk = (LONG64 *)((SIZE_T)site & ~(SIZE_T)15);
    SIZE_T off = (SIZE_T)(site - (unsigned char *)chunk);
    LONG64 old[2], want[2];
    LONG64 rel;
    LONG rel32;
    DWORD prot;
    BOOLEAN ok;

    if (off > 11 || site[0] != 0xe8)
        return 0;
    memcpy(&rel32, site + 1, 4);
    if (site + 5 + rel32 != expect)
        return 0;
    rel = (LONG64)((SIZE_T)target - (SIZE_T)(site + 5));
    if (rel > 0x7ffffff0LL || rel < -0x7ffffff0LL)
        return 0;
    rel32 = (LONG)rel;
    memcpy(old, chunk, 16);
    memcpy(want, old, 16);
    memcpy((unsigned char *)want + off + 1, &rel32, 4);
    if (!VirtualProtect(chunk, 16, PAGE_EXECUTE_READWRITE, &prot))
        return 0;
    ok = InterlockedCompareExchange128(chunk, want[1], want[0], old);
    VirtualProtect(chunk, 16, prot & ~(DWORD)PAGE_GUARD, &prot);
    FlushInstructionCache(GetCurrentProcess(), chunk, 16);
    return ok;
}

static void remove_bump(void)
{
    ULONG i;

    for (i = 0; i < BUMP_MAX_SITES; i++)
        if (bump_sites[i] && rewrite_call(bump_sites[i], (unsigned char *)hook_allocate_block, (unsigned char *)orig_allocate_block))
            bump_sites[i] = NULL;
    log_line("bump sites restored n=%ld", bump_count);
}

static void install_bump(void)
{
    unsigned char *base = (unsigned char *)GetModuleHandleA("ntdll.dll");
    unsigned char *loop, *target, *sites[BUMP_MAX_SITES];
    RUNTIME_FUNCTION *rf;
    DWORD64 image;
    ULONG matches, count, patched = 0, i;

    if (!base) {
        log_line("bump abort: ntdll not found");
        return;
    }
    loop = find_unique_sig(base, free_list_loop_sig, &matches);
    if (!loop) {
        log_line("bump abort: free list loop signature matches=%lu", matches);
        return;
    }
    rf = RtlLookupFunctionEntry((DWORD64)loop, &image, NULL);
    if (!rf) {
        log_line("bump abort: no function entry for loop rva=%#llx", (unsigned long long)(loop - base));
        return;
    }
    target = (unsigned char *)image + rf->BeginAddress;
    count = find_call_sites(base, target, sites);
    orig_allocate_block = (pfn_allocate_block)target;
    log_line("bump init ntdll=%p loop_rva=%#llx allocate_block_rva=%#llx calls=%lu hook=%p min_block=%u max_delta=%u",
             base, (unsigned long long)(loop - base), (unsigned long long)(target - base), count,
             (void *)hook_allocate_block, BUMP_MIN_BLOCK, BUMP_MAX_DELTA);
    for (i = 0; i < count; i++) {
        if (!rewrite_call(sites[i], target, (unsigned char *)hook_allocate_block)) {
            log_line("bump site %p rva=%#llx skipped", sites[i], (unsigned long long)(sites[i] - base));
            continue;
        }
        bump_sites[patched++] = sites[i];
        log_line("bump site %p rva=%#llx patched", sites[i], (unsigned long long)(sites[i] - base));
    }
    if (!patched)
        log_line("bump abort: no call site patched");
}

static DWORD WINAPI worker(LPVOID arg)
{
    char buf[32];
    int first_round = 1;
    ULONGLONG stop;

    if (GetEnvironmentVariableA("PACKFIX_DELAY", buf, sizeof buf) > 0)
        round_delay_ms = (DWORD)strtoul(buf, NULL, 10);
    if (round_delay_ms < 250)
        round_delay_ms = 250;
    if (GetEnvironmentVariableA("PACKFIX_WINDOW", buf, sizeof buf) > 0)
        total_window_ms = (DWORD)strtoul(buf, NULL, 10);

    log_line("packfix mode=%s delay=%lu window=%lu log=%s", mode, round_delay_ms, total_window_ms, log_path);
    if (strcmp(mode, "pool") == 0) {
        Sleep(round_delay_ms);
        install_hooks();
        pool_stats("installed");
    } else if (strcmp(mode, "bump") == 0) {
        Sleep(round_delay_ms);
        install_bump();
    }
    stop = GetTickCount64() + total_window_ms;
    while (GetTickCount64() < stop) {
        if (strcmp(mode, "lfh") == 0)
            enable_lfh("lfh");
        else if (strcmp(mode, "lfhbins") == 0) {
            enable_lfh("compat");
            enable_bins("lfhbins");
        }
        report_heaps(first_round ? "probe" : "report", first_round);
        if (strcmp(mode, "walk") == 0)
            walk_heaps("walk");
        else if (strcmp(mode, "pool") == 0)
            pool_stats("pool");
        else if (strcmp(mode, "bump") == 0)
            log_line("bump n=%ld", bump_count);
        first_round = 0;
        Sleep(round_delay_ms);
    }
    if (strcmp(mode, "lfh") == 0)
        enable_lfh("final");
    else if (strcmp(mode, "lfhbins") == 0)
        enable_bins("final");
    else if (strcmp(mode, "pool") == 0)
        pool_stats("pool_final");
    else if (strcmp(mode, "bump") == 0)
        log_line("bump_final n=%ld", bump_count);
    report_heaps("final", 1);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    HANDLE thread;

    if (reason == DLL_PROCESS_DETACH) {
        if (strcmp(mode, "pool") == 0) {
            pool_stats("removed");
            remove_hooks();
        } else if (strcmp(mode, "bump") == 0) {
            remove_bump();
        }
        return TRUE;
    }
    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            heap_get_process_heaps = (pfn_get_process_heaps)GetProcAddress(ntdll, "RtlGetProcessHeaps");
            heap_query_info = (pfn_query_heap_info)GetProcAddress(ntdll, "RtlQueryHeapInformation");
            heap_set_info = (pfn_set_heap_info)GetProcAddress(ntdll, "RtlSetHeapInformation");
            heap_lock = (pfn_lock_heap)GetProcAddress(ntdll, "RtlLockHeap");
            heap_unlock = (pfn_lock_heap)GetProcAddress(ntdll, "RtlUnlockHeap");
        }
    }
    GetModuleFileNameA(instance, module_path, sizeof module_path);
    pick_mode();
    build_log_path();
    log_line("packfix attached mode=%s get_heaps=%p query=%p set=%p lock=%p", mode,
             (void *)heap_get_process_heaps, (void *)heap_query_info, (void *)heap_set_info,
             (void *)heap_lock);
    thread = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    if (thread)
        CloseHandle(thread);
    return TRUE;
}

BOOL WINAPI _DllMainCRTStartup(HINSTANCE instance, DWORD reason, LPVOID reserved);

/* Wine runs DLL_PROCESS_DETACH at ExitProcess while the worker thread can still be inside CRT stdio;
   tearing down the static CRT then makes the worker fail fast with c0000409. */
BOOL WINAPI packfix_entry(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_DETACH && reserved)
        return TRUE;
    return _DllMainCRTStartup(instance, reason, reserved);
}
