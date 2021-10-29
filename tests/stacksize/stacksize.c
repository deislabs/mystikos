// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <myst/syscallext.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    register uint64_t sp __asm__("rsp");
    void* stack1;
    size_t size1;
    void* stack2;
    size_t size2;

    /* Get the stack and stack size with an extended syscall */
    assert(syscall(SYS_myst_get_process_thread_stack, &stack1, &size1) == 0);

    /* Get the stack and stack size with the pthread interface */
    {
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        assert(pthread_getattr_np(pthread_self(), &attr) == 0);
        assert(pthread_attr_getstack(&attr, &stack2, &size2) == 0);
        pthread_attr_destroy(&attr);
    }

    printf("[%p:%zu]\n", stack2, size2);
    printf("[%p:%zu]\n", stack1, size1);
    assert(stack1 == stack2);
    assert(size1 == size2);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
