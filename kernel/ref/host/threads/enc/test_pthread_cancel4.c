#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <sys/syscall.h>
#include <signal.h>
#include "posix_t.h"

int posix_printf(const char* fmt, ...);

static void* _thread_func(void *arg)
{
    (void)arg;

    for (;;)
        ;

    return NULL;
}

int test_pthread_cancel4(void)
{
    pthread_t td;
    void *res;

    posix_printf("=== %s()\n", __FUNCTION__);
    fflush(stdout);

    OE_TEST(pthread_create(&td, 0, _thread_func, NULL) == 0);
    OE_TEST(pthread_cancel(td) == 0);
    OE_TEST(pthread_join(td, &res) == 0);
    OE_TEST(res == PTHREAD_CANCELED);

    return 0;
}
