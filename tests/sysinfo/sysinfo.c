// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/sysinfo.h>

#define SLEEP_DURATION 2
int test_uptime()
{
    sleep(SLEEP_DURATION);
    struct sysinfo si = {0};
    sysinfo(&si);

    return si.uptime >= SLEEP_DURATION;
}

#define RUNS 10000
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
    int pthread_count = 10;
    pthread_t tid[10];
    int exit_flag[10] = {0};
    for (int i = 0; i < 10; i++)
    {
        pthread_create(&tid[i], NULL, incr, &exit_flag[i]);
    }

    while (count != 10)
    {
        sleep(1);
    }
    struct sysinfo si = {0};
    sysinfo(&si);
    assert(si.procs == 11); // main thread + 10 child threads

    for (int i = 0; i < 10; i++)
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

int main(int argc, const char* argv[])
{
    assert(test_uptime());
    test_procs();
    test_unsupported_fields_are_zero();

    printf("\n=== passed test (%s)\n", argv[0]);

    return 0;
}
