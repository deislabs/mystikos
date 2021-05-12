// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../utils/utils.h"

const size_t N = 256;
static int fd;

static void* _read_thread(void* arg)
{
    long slow = (long)arg;

    for (size_t i = 0; i < N; i++)
    {
        uint64_t val = 0;

        if (slow)
            sleep_msec(3);

        ssize_t n = read(fd, &val, sizeof(val));
        assert(n == sizeof(val));
    }

    return NULL;
}

static void* _write_thread(void* arg)
{
    long slow = (long)arg;

    for (size_t i = 0; i < N; i++)
    {
        if (slow)
            sleep_msec(3);

        uint64_t val = 1;
        ssize_t n = write(fd, &val, sizeof(val));
        assert(n == sizeof(uint64_t));
    }

    return NULL;
}

static void _dump_stat_buf(struct stat* buf)
{
    printf("st_dev=%lu\n", buf->st_dev);
    printf("st_ino=%lu\n", buf->st_ino);
    printf("st_mode=%o\n", buf->st_mode);
    printf("st_nlink=%lu\n", buf->st_nlink);
    printf("st_uid=%d\n", buf->st_uid);
    printf("st_gid=%d\n", buf->st_gid);
    printf("st_rdev=%lu\n", buf->st_rdev);
    printf("st_size=%zu\n", buf->st_size);
    printf("st_blksize=%zu\n", buf->st_blksize);
    printf("st_blocks=%zu\n", buf->st_blocks);
}

void test_eventfd(long slow_write, long slow_read)
{
    const size_t NUM_THREADS = 2;
    pthread_t threads[NUM_THREADS];
    const char* msg1 = slow_write ? "slow-writer" : "fast-writer";
    const char* msg2 = slow_read ? "slow-reader" : "fast-reader";

    printf("=== start test (%s: %s/%s)\n", __FUNCTION__, msg1, msg2);

    fd = eventfd(0, EFD_SEMAPHORE);
    assert(fd >= 0);

    /* Create the reader thread */
    if (pthread_create(&threads[0], NULL, _read_thread, (void*)slow_write) != 0)
    {
        fprintf(stderr, "pthread_create() failed\n");
        abort();
    }

    /* Create the write thread */
    if (pthread_create(&threads[1], NULL, _write_thread, (void*)slow_read) != 0)
    {
        fprintf(stderr, "pthread_create() failed\n");
        abort();
    }

    /* Join the threads */
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        void* retval;

        if (pthread_join(threads[i], &retval) != 0)
        {
            fprintf(stderr, "pthread_join() failed\n");
            abort();
        }
    }

    close(fd);

    printf("=== passed test (%s: %s/%s)\n", __FUNCTION__, msg1, msg2);
}

void test1(void)
{
    /* test fast-writer/fast-reader */
    test_eventfd(0, 0);

    /* test fast-writer/slow-reader */
    test_eventfd(0, 1);

    /* test slow-writer/fast-reader */
    test_eventfd(1, 0);

    /* test slow-writer/slow-reader */
    test_eventfd(1, 1);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void* _child(void* arg)
{
    for (uint64_t i = 0; i < N; i++)
        assert(write(fd, &i, sizeof(i)) == sizeof(uint64_t));

    return NULL;
}

void test2(void)
{
    pthread_t thread;
    void* retval;

    fd = eventfd(0, 0);
    assert(fd >= 0);

    if (pthread_create(&thread, NULL, _child, NULL) != 0)
    {
        fprintf(stderr, "pthread_create() failed\n");
        abort();
    }

    if (pthread_join(thread, &retval) != 0)
    {
        fprintf(stderr, "pthread_join() failed\n");
        abort();
    }

    const uint64_t expect = ((N - 1) * ((N - 1) + 1)) / 2;

    uint64_t val = 0;
    assert(read(fd, &val, sizeof(val)) == sizeof(uint64_t));
    assert(val == expect);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    test1();
    test2();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
