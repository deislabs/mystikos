#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>

static volatile int _uaddr = 0;

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_PRIVATE 128

void* start_routine(void* arg)
{
    printf("\n");

    for (size_t i = 0; i < 3; i++)
    {
        printf("sleep...\n");
        fflush(stdout);
        sleep(1);
    }

    return arg;
}

int main(int argc, const char* argv[])
{
    pthread_t pt;
    int r;
    long ret;
    void* arg;
    void* arg_expected = (void*)0x12345678;

    _uaddr = 1;

    r = pthread_create(&pt, NULL, start_routine, arg_expected);
    printf("pthread_create(): %d\n", r);
    assert(r == 0);

    r = pthread_join(pt, &arg);
    printf("pthread_join(): %d %p\n", r, arg);
    assert(r == 0);
    assert(arg == arg_expected);

    return 0;
}
