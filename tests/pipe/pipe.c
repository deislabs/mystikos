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
#include <sys/stat.h>
#include <unistd.h>

static int pipefd[2];

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

static ssize_t _writen(int fd, const void* data, size_t size)
{
    ssize_t ret = 0;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;

    while (r > 0)
    {
        ssize_t n = write(fd, p, r);

        if (n <= 0)
        {
            ret = -1;
            goto done;
        }

        p += n;
        r -= (size_t)n;
    }

done:

    return ret;
}

static ssize_t _readn(int fd, void* data, size_t size)
{
    ssize_t ret = 0;
    uint8_t* p = (uint8_t*)data;
    size_t r = size;

    while (r > 0)
    {
        ssize_t n = read(fd, p, r);

        if (n <= 0)
        {
            ret = -1;
            goto done;
        }

        p += n;
        r -= (size_t)n;
    }

done:

    return ret;
}

static char ALPHABET[] = "abcdefghijklmnopqrstuvwxyz";

const size_t N = 256;

static void* _read_thread(void* arg)
{
    long slow = (long)arg;

    for (size_t i = 0; i < N; i++)
    {
        char buf[sizeof(ALPHABET)];

        if (slow)
            sleep_msec(3);

        memset(buf, 0, sizeof(buf));
        ssize_t n = _readn(pipefd[0], buf, sizeof(buf));
        assert(n == 0);
        assert(memcmp(buf, ALPHABET, sizeof(ALPHABET)) == 0);
    }

    close(pipefd[0]);

    return NULL;
}

static void* _write_thread(void* arg)
{
    long slow = (long)arg;

    for (size_t i = 0; i < N; i++)
    {
        if (slow)
            sleep_msec(3);

        ssize_t n = _writen(pipefd[1], ALPHABET, sizeof(ALPHABET));
        assert(n == 0);
    }

    close(pipefd[1]);

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

void test_pipes(long slow_write, long slow_read)
{
    const size_t NUM_THREADS = 2;
    pthread_t threads[NUM_THREADS];
    const char* msg1 = slow_write ? "slow-writer" : "fast-writer";
    const char* msg2 = slow_read ? "slow-reader" : "fast-reader";

    printf("=== start test (%s: %s/%s)\n", __FUNCTION__, msg1, msg2);

    /* Create the pipe */
    /* ATTN: test flags later */
    assert(pipe2(pipefd, 0) == 0);

    /* Stat the pipe */
    {
        struct stat buf0;
        assert(fstat(pipefd[0], &buf0) == 0);
        assert(buf0.st_blksize == PIPE_BUF);

        struct stat buf1;
        assert(fstat(pipefd[1], &buf1) == 0);
        assert(buf1.st_blksize == PIPE_BUF);

        (void)_dump_stat_buf;
    }

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

    printf("=== passed test (%s: %s/%s)\n", __FUNCTION__, msg1, msg2);
}

int main(int argc, const char* argv[])
{
    /* test fast-writer/fast-reader */
    test_pipes(0, 0);

    /* test fast-writer/slow-reader */
    test_pipes(0, 1);

    /* test slow-writer/fast-reader */
    test_pipes(1, 0);

    /* test slow-writer/slow-reader */
    test_pipes(1, 1);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
