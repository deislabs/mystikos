// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <lthread.h>
#include <openenclave/enclave.h>
#include "run_t.h"

#define TIMEOUT_MSEC 1

#define NUM_THREADS 10

#define NUM_ITERATIONS 10

int oe_host_printf(const char* fmt, ...);
int oe_snprintf(char* str, size_t size, const char* format, ...);
uint64_t lthread_id();

void lthread_exit(void* ptr);

static void _child_thread(void* arg)
{
    bool detached = *(bool*)arg;

    if (detached)
        lthread_detach();

    for (size_t i = 0; i < NUM_ITERATIONS; i++)
    {
        uint64_t ltid = lthread_id();
        // oe_host_printf("=== thread: %lu\n", ltid);
        lthread_sleep(ltid * TIMEOUT_MSEC);
    }

    lthread_exit(NULL);
}

static void _main_thread(void* arg)
{
    bool detached = *(bool*)arg;
    const size_t N = NUM_THREADS;
    lthread_t* lt[N];

    (void)arg;

    lthread_detach();

    /* Create N lthreads */
    for (size_t i = 0; i < N; i++)
        lthread_create(&lt[i], _child_thread, arg);

    if (!detached)
    {
        for (size_t i = 0; i < N; i++)
            lthread_join(lt[i], NULL, 0);
    }
}

static void _run(bool detached)
{
    lthread_t* lt;

    // oe_host_printf("=== %s(): enter\n", __FUNCTION__);

    /* create the main lthread */
    lthread_create(&lt, _main_thread, &detached);
    lthread_run();

    // oe_host_printf("=== %s(): leave\n\n", __FUNCTION__);
}

int run_ecall(void)
{
    _run(true);
    _run(false);
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    4096, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
