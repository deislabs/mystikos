#include <pthread.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <syscall.h>
#include <stdint.h>
#include <errno.h>

static volatile int _uaddr = 0;

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_PRIVATE 128

void sleep_msec(uint64_t milliseconds)
{
    struct timespec ts;
    const struct timespec* req = &ts;
    struct timespec rem = {0, 0};
    static const uint64_t _SEC_TO_MSEC = 1000UL;
    static const uint64_t _MSEC_TO_NSEC = 1000000UL;

    ts.tv_sec = (time_t)(milliseconds / _SEC_TO_MSEC);
    ts.tv_nsec = (long)((milliseconds % _SEC_TO_MSEC) * _MSEC_TO_NSEC);

    while (nanosleep(req, &rem) != 0 && errno == EINTR)
    {
        req = &rem;
    }
}

void* start_routine(void* arg)
{
    printf("\n");

    for (size_t i = 0; i < 5; i++)
    {
        printf("sleep...\n");
        fflush(stdout);
        sleep_msec(10);
    }

    _uaddr = 0;
    syscall(SYS_futex, &_uaddr, FUTEX_WAKE | FUTEX_PRIVATE, 1);

    return arg;
}

int main(int argc, const char* argv[])
{
    pthread_t pt;
    int r;
    long ret;

    r = pthread_create(&pt, NULL, start_routine, (void*)0xabcd);
    printf("pthread_create(): return: %d\n", r);

    _uaddr = 1;
    ret = syscall(SYS_futex, &_uaddr, FUTEX_WAIT | FUTEX_PRIVATE, 1);
    printf("pthread_create(): syscall: %ld\n", ret);

    return 0;
}
