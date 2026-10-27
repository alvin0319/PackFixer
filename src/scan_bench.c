#include <windows.h>
#include <stdio.h>
#include <string.h>

#define HOLES 9000
#define DIRECT 1000
#define GROUPS 1000
#define GROUP_BLOCKS 31
#define SMALL 40
#define WARM 0x900
#define TARGET 1512

static void *warm[WARM];
static void *holes[HOLES];
static void *keepers[HOLES];
static void *direct_before[DIRECT];
static void *direct_after[DIRECT];
static void *small_before[GROUPS * GROUP_BLOCKS];
static void *small_after[GROUPS * GROUP_BLOCKS];

static double seconds_since(LARGE_INTEGER start)
{
    LARGE_INTEGER now, freq;
    QueryPerformanceCounter(&now);
    QueryPerformanceFrequency(&freq);
    return (double)(now.QuadPart - start.QuadPart) / (double)freq.QuadPart;
}

static double timed_allocs(HANDLE heap, void **out, int count, SIZE_T size)
{
    LARGE_INTEGER start;
    int i;

    QueryPerformanceCounter(&start);
    for (i = 0; i < count; i++)
        out[i] = HeapAlloc(heap, 0, size);
    return seconds_since(start);
}

static int verify(HANDLE heap, void **blocks, int count, SIZE_T size)
{
    int i;
    SIZE_T j;

    for (i = 0; i < count; i++) {
        if (!blocks[i] || HeapSize(heap, 0, blocks[i]) != size)
            return 1;
        memset(blocks[i], i & 0xff, size);
    }
    for (i = 0; i < count; i++)
        for (j = 0; j < size; j++)
            if (((unsigned char *)blocks[i])[j] != (unsigned char)(i & 0xff))
                return 2;
    return 0;
}

static void release(HANDLE heap, void **blocks, int count)
{
    int i;

    for (i = 0; i < count; i++)
        HeapFree(heap, 0, blocks[i]);
}

int main(void)
{
    HANDLE heap = HeapCreate(0, 0, 0);
    char path[260];
    double direct_t[2], small_t[2];
    int i, rc;

    if (!heap)
        return 1;
    for (i = 0; i < WARM; i++)
        warm[i] = HeapAlloc(heap, 0, SMALL);
    for (i = 0; i < HOLES; i++) {
        holes[i] = HeapAlloc(heap, 0, 1272 + (i % 15) * 16);
        keepers[i] = HeapAlloc(heap, 0, 1592 + (i % 150) * 16);
        if (!holes[i] || !keepers[i])
            return 1;
    }
    release(heap, holes, HOLES);

    direct_t[0] = timed_allocs(heap, direct_before, DIRECT, TARGET);
    small_t[0] = timed_allocs(heap, small_before, GROUPS * GROUP_BLOCKS, SMALL);
    if (GetEnvironmentVariableA("PACKFIX_TEST_DLL", path, sizeof path)) {
        printf("load=%p path=%s\n", (void *)LoadLibraryA(path), path);
        fflush(stdout);
        Sleep(3000);
    }
    direct_t[1] = timed_allocs(heap, direct_after, DIRECT, TARGET);
    small_t[1] = timed_allocs(heap, small_after, GROUPS * GROUP_BLOCKS, SMALL);

    rc = verify(heap, direct_before, DIRECT, TARGET) | verify(heap, direct_after, DIRECT, TARGET) << 2 |
         verify(heap, small_before, GROUPS * GROUP_BLOCKS, SMALL) << 4 |
         verify(heap, small_after, GROUPS * GROUP_BLOCKS, SMALL) << 6;
    printf("direct ms/alloc before=%.4f after=%.4f group ms/group before=%.4f after=%.4f rc=%d\n",
           direct_t[0] * 1000.0 / DIRECT, direct_t[1] * 1000.0 / DIRECT,
           small_t[0] * 1000.0 / GROUPS, small_t[1] * 1000.0 / GROUPS, rc);
    fflush(stdout);
    release(heap, direct_before, DIRECT);
    release(heap, direct_after, DIRECT);
    release(heap, small_before, GROUPS * GROUP_BLOCKS);
    release(heap, small_after, GROUPS * GROUP_BLOCKS);
    release(heap, keepers, HOLES);
    release(heap, warm, WARM);
    HeapDestroy(heap);
    return rc;
}
