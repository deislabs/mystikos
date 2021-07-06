// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

int counter = 0;
static void* _thread_func(void* arg)
{
    struct rlimit nofile_limit;
    nofile_limit.rlim_cur = 1024;
    nofile_limit.rlim_max = 1024;
    // setrlimit causes a SIG_SYNCCALL to be sent to the thread group
    // As the parent thread is joined on this thread. It will have to be
    // woken up to deliver the signal.
    setrlimit(RLIMIT_NOFILE, &nofile_limit);
    printf("Going to sleep\n");
    counter++;
    sleep(2);
    printf("Woke up. Now exiting\n");
    counter++;
    return arg;
}

int main(int argc, const char* argv[])
{
    pthread_t thread;
    int ret = pthread_create(&thread, NULL, _thread_func, NULL);
    pthread_join(thread, NULL);
    printf("After join\n");
    assert(counter == 2); // check all child events were recorded
    printf("\n=== passed test (%s)\n", argv[0]);
    return 0;
}