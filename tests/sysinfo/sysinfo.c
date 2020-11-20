// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/time.h>

#define SLEEP_DURATION 1
#define THREAD_COUNT 4

int test_uptime()
{
    sleep(SLEEP_DURATION);
    struct sysinfo si = {0};
    sysinfo(&si);

    return si.uptime >= SLEEP_DURATION;
}

_Atomic int count;
void* incr(void* args)
{
    int* should_exit = (int*)args;
    count++;
    while (!*should_exit)
    {
        sleep(1);
    }
}

void test_procs()
{
    pthread_t tid[THREAD_COUNT];
    int exit_flag[THREAD_COUNT] = {0};
    for (int i = 0; i < THREAD_COUNT; i++)
    {
        pthread_create(&tid[i], NULL, incr, &exit_flag[i]);
    }

    while (count != THREAD_COUNT)
    {
        sleep(1);
    }
    struct sysinfo si = {0};
    sysinfo(&si);
    assert(si.procs == THREAD_COUNT + 1); // main thread + 10 child threads

    for (int i = 0; i < THREAD_COUNT; i++)
    {
        exit_flag[i] = 1;
        pthread_join(tid[i], NULL);
    }
}

void test_unsupported_fields_are_zero()
{
    struct sysinfo si = {0};
    sysinfo(&si);

    assert(si.loads[0] == 0);
    assert(si.loads[1] == 0);
    assert(si.loads[2] == 0);
    assert(si.sharedram == 0);
    assert(si.bufferram == 0);
    assert(si.totalswap == 0);
    assert(si.freeswap == 0);
    assert(si.totalhigh == 0);
    assert(si.freehigh == 0);
}

void test_getrusage()
{
    const int MICRO_IN_SECOND = 1000000;

    int who = RUSAGE_SELF;
    struct rusage usage = {0};

    assert(getrusage(who, &usage) == 0);

    // We have sleeped in the previously executed test_uptime
    // for SLEEP_DURATION seconds. It's safe to assert utime
    // and stime are greater than it.
    assert(usage.ru_utime.tv_sec * MICRO_IN_SECOND + usage.ru_utime.tv_usec >
            SLEEP_DURATION * MICRO_IN_SECOND);
    assert(usage.ru_stime.tv_sec * MICRO_IN_SECOND + usage.ru_stime.tv_usec >
            SLEEP_DURATION * MICRO_IN_SECOND);
    assert(usage.ru_maxrss == 0);        /* maximum resident set size */
    assert(usage.ru_ixrss == 0);         /* integral shared memory size */
    assert(usage.ru_idrss == 0);         /* integral unshared data size */
    assert(usage.ru_isrss == 0);         /* integral unshared stack size */
    assert(usage.ru_minflt == 0);        /* page reclaims (soft page faults) */
    assert(usage.ru_majflt == 0);        /* page faults (hard page faults) */
    assert(usage.ru_nswap == 0);         /* swaps */
    assert(usage.ru_inblock == 0);       /* block input operations */
    assert(usage.ru_oublock == 0);       /* block output operations */
    assert(usage.ru_msgsnd == 0);        /* IPC messages sent */
    assert(usage.ru_msgrcv == 0);        /* IPC messages received */
    assert(usage.ru_nsignals == 0);      /* signals received */
    assert(usage.ru_nvcsw == 0);         /* voluntary context switches */
    assert(usage.ru_nivcsw == 0);        /* involuntary context switches */
}

int main(int argc, const char* argv[])
{
    assert(test_uptime());
    test_procs();
    test_unsupported_fields_are_zero();

    test_getrusage();

    printf("\n=== passed test (%s)\n", argv[0]);

    return 0;
}
