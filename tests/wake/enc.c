// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <lthread.h>
#include "run_t.h"

#define TIMEOUT_MSEC 100

#define NUM_ITERATIONS 10

#define PRINTF oe_host_printf

int oe_host_printf(const char* fmt, ...);

static void _wait_thread(void* arg)
{
    lthread_detach();

    (void)arg;

    for (size_t i = 0; i < NUM_ITERATIONS; i++)
    {
        PRINTF("wait...\n");
        lthread_sleep(5 * TIMEOUT_MSEC);
    }

    PRINTF("done...\n");
    lthread_exit(NULL);
}

static void _wake_thread(void* arg)
{
    lthread_t* lt = (lthread_t*)arg;
    lthread_detach();

    for (size_t i = 0; i < NUM_ITERATIONS; i++)
    {
        lthread_sleep(TIMEOUT_MSEC);
        PRINTF("wake...\n");
        lthread_wakeup(lt);
    }

    lthread_exit(NULL);
}

int run_ecall(void)
{
    lthread_t* wait_lt = NULL;
    lthread_t* wake_lt = NULL;

    oe_host_printf("=== %s(): enter\n", __FUNCTION__);

    /* create the main lthread */
    lthread_create(&wait_lt, _wait_thread, NULL);
    lthread_create(&wake_lt, _wake_thread, wait_lt);
    (void)wake_lt;
    lthread_run();

    oe_host_printf("=== %s(): leave\n\n", __FUNCTION__);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    16*4096, /* NumHeapPages */
    4096, /* NumStackPages */
    2);   /* NumTCS */
