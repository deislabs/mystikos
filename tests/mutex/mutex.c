// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>

// musl libc does not have PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
// clang-format off
#ifndef PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
#define PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP { 0, 0, 0, 0, 1, 0, 0, 0, 0, 0 }
#endif
// clang-format on

int main(int argc, const char* argv[])
{
    /* try relocking a statically-initialized non-recursive mutex */
    {
        static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
        assert(pthread_mutex_lock(&m) == 0);
        assert(pthread_mutex_trylock(&m) == EBUSY);
    }

    /* try relocking a statically-initialized recursive mutex */
    {
        static pthread_mutex_t m = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
        assert(pthread_mutex_lock(&m) == 0);
        assert(pthread_mutex_trylock(&m) == 0);
    }

    /* try relocking a dynamically-initialized recursive mutex */
    {
        pthread_mutex_t m;
        pthread_mutexattr_t a;
        assert(pthread_mutexattr_init(&a) == 0);
        assert(pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE) == 0);
        assert(pthread_mutex_init(&m, &a) == 0);
        assert(pthread_mutex_lock(&m) == 0);
        assert(pthread_mutex_trylock(&m) == 0);
        assert(pthread_mutex_destroy(&m) == 0);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
