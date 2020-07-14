// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <lthread.h>
#include "calls_t.h"

#define TIMEOUT_MSEC 0

int oe_host_printf(const char* fmt, ...);
int oe_snprintf(char* str, size_t size, const char* format, ...);
uint64_t lthread_id();

void lthread_exit(void *ptr);

//#define DETACHED

static void _child_thread(void* arg)
{
#ifdef DETACHED
    lthread_detach();
#endif

    for (size_t i = 0; i < 10; i++)
    {
        uint64_t ltid = lthread_id();
        oe_host_printf("=== thread: %lu\n", ltid);
        lthread_sleep(ltid * TIMEOUT_MSEC);
    }

#ifndef DETACHED
    //lthread_exit(NULL);
#endif
}

static void _main_thread(void* arg)
{
    const size_t N = 10;
    lthread_t* lt[N];

    (void)arg;

    lthread_detach();

    oe_host_printf("=== main thread: enter\n");

    /* Create N lthreads */
    for (size_t i = 0; i < N; i++)
        lthread_create(&lt[i], _child_thread, NULL);

#ifdef DETACHED
    //lthread_run();
#else
    for (size_t i = 0; i < N; i++)
    {
oe_host_printf("JOIN{%zu}\n", i);
        lthread_join(lt[i], NULL, 0);
    }
#endif

    oe_host_printf("=== main thread: leave\n");
}

int lthread_ecall(void)
{
    lthread_t* lt;

    oe_host_printf("=== lthread_ecall(): enter\n");

    /* create the main lthread */
    lthread_create(&lt, _main_thread, NULL);
    lthread_run();

    oe_host_printf("=== lthread_ecall(): leave\n");

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    4096, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
