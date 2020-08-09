#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>

#define VAL 0x12345678

static void* _thread_func(void *arg)
{
    uint32_t* val = (uint32_t*)arg;

    *val = VAL;
    sleep(2);

    return 0;
}

int test_pthread_cancel1(void)
{
    pthread_t td;
    void *res;
    uint32_t val = 0;

    printf("=== test_pthread_cancel1()\n");
    fflush(stdout);

    OE_TEST(pthread_create(&td, 0, _thread_func, &val) == 0);
    sleep(1);
    OE_TEST(pthread_cancel(td) == 0);
    OE_TEST(pthread_join(td, &res) == 0);
    OE_TEST(res == PTHREAD_CANCELED);
    OE_TEST(val == VAL);

    return 0;
}
