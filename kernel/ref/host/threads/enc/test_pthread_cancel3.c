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

#define posix_printf printf

static void* _thread_func(void *arg)
{
    (void)arg;

    posix_printf("tttttttttttttttttttttttttttttttttttttttttt\n");
    posix_printf("tttttttttttttttttttttttttttttttttttttttttt\n");

    for (;;)
        ;

    return NULL;
}

int test_pthread_cancel3(void)
{
    pthread_t td;
    void *res;

    //posix_printf("=== test_pthread_cancel3()\n");
    //fflush(stdout);

    OE_TEST(pthread_create(&td, 0, _thread_func, NULL) == 0);
    OE_TEST(pthread_cancel(td) == 0);
    OE_TEST(pthread_join(td, &res) == 0);
    OE_TEST(res == PTHREAD_CANCELED);

    return 0;
}
