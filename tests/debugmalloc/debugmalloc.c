// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
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

int main(int argc, const char* argv[])
{
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
