#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static int read_clock(char* msg, clockid_t clk_id, struct timespec* ts)
{
    int ret = clock_gettime(clk_id, ts);
    if (!ret)
    {
        printf("%s: %ld secs %ld nsecs\n", msg, ts->tv_sec, ts->tv_nsec);
        // time shouldn't be negative
        assert(ts->tv_sec >= 0);
        assert(ts->tv_nsec >= 0);
    }
    return ret;
}

static int write_clock(clockid_t clk_id)
{
    struct timespec ts;
    int ret = clock_settime(clk_id, &ts);
    return ret;
}

// spend some cycles in userland
static int scan_array()
{
    int sum, arr[10000];
    for (int i = 0; i < 10000; i++)
        sum += arr[i];
    return sum;
}

static pthread_spinlock_t _lock;
static bool _quit_thread_func;

static _Atomic(bool) _thread_started;

static void* thread_func(void* arg)
{
    _thread_started = true;

    while (1)
    {
        pthread_spin_lock(&_lock);
        bool quit = _quit_thread_func;
        pthread_spin_unlock(&_lock);

        if (quit)
            break;

        scan_array();
        sleep(1);
    }
}

static long ts_to_long(struct timespec* ts)
{
    return ts->tv_sec + ts->tv_nsec;
}

int main(int argc, char* argv[])
{
    pthread_t thread;
    clockid_t cid;
    int ret;
    struct timespec ts = {0};

    pthread_spin_init(&_lock, PTHREAD_PROCESS_PRIVATE);

    ret = pthread_create(&thread, NULL, thread_func, NULL);

    /* wait for _thread_func() to be called */
    while (!_thread_started)
        __asm__ __volatile__("pause" : : : "memory");

    scan_array();
    assert(read_clock("main's thread time", CLOCK_THREAD_CPUTIME_ID, &ts) == 0);

    int pid = getpid();
    clock_getcpuclockid(pid, &cid);
    assert(read_clock("main's clock_getcpuclockid time", cid, &ts) == 0);
    // test clock_getcpuclockid clocks not settable
    assert(write_clock(cid) != 0);

    struct timespec main_thread_ts = {0};
    scan_array();
    pthread_getcpuclockid(pthread_self(), &cid);
    assert(
        read_clock("main's pthread clockid time", cid, &main_thread_ts) == 0);

    scan_array();
    struct timespec child_thread_ts = {0};
    pthread_getcpuclockid(thread, &cid);
    assert(
        read_clock("child's pthread clockid time", cid, &child_thread_ts) == 0);
    // test pthread_getcpuclockid clocks not settable
    assert(write_clock(cid) != 0);

    struct timespec process_ts = {0};
    assert(
        read_clock(
            "main's process time", CLOCK_PROCESS_CPUTIME_ID, &process_ts) == 0);
    assert(
        ts_to_long(&process_ts) >
        ts_to_long(&child_thread_ts) + ts_to_long(&main_thread_ts));

    /* prevent the thread clone structures from being leaked */
    {
        pthread_spin_lock(&_lock);
        _quit_thread_func = true;
        pthread_spin_unlock(&_lock);
        sleep(1);
        pthread_join(thread, NULL);
    }

    pthread_spin_destroy(&_lock);

    printf("=== passed test (%s)\n", argv[0]);
    exit(0);
}
