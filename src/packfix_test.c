#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCKS 600
#define THREADS 8
#define CHURN 50000

static int churn(void *arg)
{
    int id = (int)(intptr_t)arg;
    char *prev = NULL;
    SIZE_T prev_len = 0;
    unsigned char prev_pat = 0;
    int i;

    for (i = 0; i < CHURN; i++) {
        SIZE_T len = 16 + (SIZE_T)((i + id) % 900) * 32;
        unsigned char pat = (unsigned char)(i + id);
        char *p = malloc(len);
        SIZE_T j;
        if (!p)
            return 1;
        memset(p, pat, len);
        if (prev) {
            for (j = 0; j < prev_len; j++)
                if ((unsigned char)prev[j] != prev_pat)
                    return 2;
            free(prev);
        }
        prev = p;
        prev_len = len;
        prev_pat = pat;
    }
    if (prev)
        free(prev);
    return 0;
}

static int zero_check(void)
{
    char *a = malloc(1520);
    char *b;
    int i;

    if (!a)
        return 1;
    memset(a, 0xaa, 1520);
    free(a);
    b = calloc(1520, 1);
    if (!b)
        return 1;
    for (i = 0; i < 1520; i++)
        if (b[i])
            return 5;
    free(b);
    return 0;
}

int main(void)
{
    static void *keep[BLOCKS];
    static const SIZE_T sizes[] = {0x9000, 0x21000, 0x45000, 0x81000};
    char path[260];
    HMODULE module;
    ULONGLONG start;
    int i;

    for (i = 0; i < BLOCKS; i++)
        keep[i] = malloc(sizes[i % 4]);
    for (i = 1; i < BLOCKS; i += 2)
    {
        free(keep[i]);
        keep[i] = NULL;
    }

    if (!GetEnvironmentVariableA("PACKFIX_TEST_DLL", path, sizeof path))
        snprintf(path, sizeof path, "Z:\\home\\minjae\\CLionProjects\\PackFixer\\build\\packfix_report.dll");
    module = LoadLibraryA(path);

    printf("load=%p err=%lu path=%s\n", (void *)module, GetLastError(), path);
    fflush(stdout);
    Sleep(4000);
    start = GetTickCount64();
    {
        HANDLE th[THREADS];
        DWORD code;
        for (i = 0; i < THREADS; i++)
            th[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)churn, (void *)(intptr_t)i, 0, NULL);
        for (i = 0; i < THREADS; i++) {
            if (!th[i])
                return 1;
            WaitForSingleObject(th[i], INFINITE);
            GetExitCodeThread(th[i], &code);
            CloseHandle(th[i]);
            if (code) {
                printf("churn fail rc=%lu\n", code);
                fflush(stdout);
                return (int)code;
            }
        }
        code = (DWORD)zero_check();
        if (code) {
            printf("zero fail rc=%lu\n", code);
            fflush(stdout);
            return (int)code;
        }
    }
    printf("churn ok in %llu ms\n", (unsigned long long)(GetTickCount64() - start));
    fflush(stdout);
    for (i = 0; i < BLOCKS; i++)
        if (keep[i])
            free(keep[i]);
    return 0;
}
