// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/syscall.h>

static void* a_ptr;
static void* b_ptr;
static void* c_ptr;

void c()
{
    c_ptr = malloc(13);
}

void b()
{
    b_ptr = malloc(45);
    c();
}

void a()
{
    a_ptr = malloc(99);
    b();
}

size_t debug_malloc_check(bool print_allocations)
{
    const long SYS_myst_debug_malloc_check = 2021;
    size_t count = (size_t)syscall(
        SYS_myst_debug_malloc_check, (long)print_allocations);
    return count;
}

/* set a breakpoint here and try this gdb command: "info line *<addr>" */
void stop()
{
}

void test_malloc()
{
    void** ptrs;
    size_t* sizes;
    const size_t n = 1024*10;

    if (!(ptrs = calloc(n, sizeof(void*))))
    {
        fprintf(stderr, "calloc() failed\n");
        exit(1);
    }

    if (!(sizes = calloc(n, sizeof(size_t))))
    {
        fprintf(stderr, "calloc() failed\n");
        exit(1);
    }

    /* malloc */
    for (size_t i = 0; i < n; i++)
    {
        size_t size = rand() % 64 + 1;

        if (!(ptrs[i] = memalign(128, size)))
        {
            fprintf(stderr, "memalign() failed\n");
            exit(1);
        }

        memset(ptrs[i], '\0', size);
        sizes[i] = size;
    }

    /* realloc */
    for (size_t i = 0; i < n; i++)
    {
        size_t size = rand() % 128 + 1;

        memset(ptrs[i], '\0', sizes[i]);

        if (!(ptrs[i] = realloc(ptrs[i], size)))
        {
            fprintf(stderr, "malloc() failed\n");
            exit(1);
        }

        memset(ptrs[i], '\0', size);
        sizes[i] = size;
    }

    /* clear */
    for (size_t i = 0; i < n; i++)
    {
        memset(ptrs[i], '\0', sizes[i]);
    }

    /* free every other and allocate new */
    for (size_t i = 0; i < n; i += 2)
    {
        size_t size = rand() % 128 + 1;

        memset(ptrs[i], '\0', sizes[i]);
        free(ptrs[i]);
        ptrs[i] = NULL;
        sizes[i] = 0;

        if (!(ptrs[i] = malloc(size)))
        {
            fprintf(stderr, "malloc() failed\n");
            exit(1);
        }

        memset(ptrs[i], '\0', size);
        sizes[i] = size;
    }

    /* free */
    for (size_t i = 0; i < n; i++)
    {
        memset(ptrs[i], '\0', sizes[i]);
        free(ptrs[i]);
        sizes[i] = 0;
        ptrs[i] = NULL;
    }

    free(ptrs);
    free(sizes);
}

void test_malloc2()
{
    void* ptr;

    if (!(ptr = memalign(256, 16)))
    {
        fprintf(stderr, "memalign() failed\n");
        exit(1);
    }
    free(ptr);
}

int main(int argc, const char* argv[])
{
    test_malloc();
    debug_malloc_check(true);

    size_t count;
    a();

    assert(a_ptr);
    assert(b_ptr);
    assert(c_ptr);

    debug_malloc_check(true);
    stop();

    assert(debug_malloc_check(false) == 3);
    free(c_ptr);
    assert(debug_malloc_check(false) == 2);
    free(b_ptr);
    assert(debug_malloc_check(false) == 1);
    free(a_ptr);
    assert(debug_malloc_check(false) == 0);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
