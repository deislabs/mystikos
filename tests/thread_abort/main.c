// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void* thread_func1(void* arg)
{
    printf("In child thread: expecting assertion failure ...\n");
    assert(0);
    // Unreachable
    return NULL;
}

void test_child_abort()
{
    pthread_t t;

    pthread_create(&t, NULL, thread_func1, NULL);

    printf("In main thread: before sleep...\n");
    sleep(3);
    printf("In main thread: after sleep. We should not be here...\n");
    assert(0);
}

int main()
{
    test_child_abort();
    return 0;
}