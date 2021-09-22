// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
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

/*
**==============================================================================
**
** test_pipes()
**
**==============================================================================
*/

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

    assert(fcntl(pipefd[0], F_SETPIPE_SZ, 4096) == 0);
    assert(fcntl(pipefd[1], F_SETPIPE_SZ, 4096) == 0);

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

/*
**==============================================================================
**
** test_pipe_size()
**
**==============================================================================
*/

void test_pipe_size(void)
{
    int fds[2];
    ssize_t n = 0;
    char buf[4096];

    printf("=== start test (%s)\n", __FUNCTION__);

    assert(pipe(fds) == 0);

    /* check that fds[1] is already write enabled */
    {
        struct pollfd pollfd = {.fd = fds[1], .events = POLLOUT};
        int r = poll(&pollfd, 1, 1);
        assert(r == 1);
    }

    memset(buf, 0, sizeof(buf));

    /* Get the pipe size */
    long pipesz = (long)fcntl(fds[1], F_GETPIPE_SZ);

    /* write pages to the pipe until no longer write-enabled */
    for (;;)
    {
        ssize_t r = write(fds[1], buf, sizeof(buf));
        assert(r == sizeof(buf));
        n += r;

        struct pollfd pollfd = {.fd = fds[1], .events = POLLOUT};
        int nfds = poll(&pollfd, 1, 1);
        assert(nfds != -1);

        if (nfds == 0)
            break;

        if (n < 0)
            break;
    }

    /* compare with the pipe obtained with fcntl() */
    assert(n == pipesz);

    /* try to read pipesz data */
    {
        void* data;

        assert((data = malloc(pipesz)) != NULL);
        assert(read(fds[0], data, pipesz) == pipesz);
    }

    /* check that fds[1] is write enabled */
    {
        struct pollfd pollfd = {.fd = fds[1], .events = POLLOUT};
        int r = poll(&pollfd, 1, 1);
        assert(r == 1);
    }

    close(fds[0]);
    close(fds[1]);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
**==============================================================================
**
** test_multiple_readers_writers()
**
**==============================================================================
*/

typedef struct test_multiple_readers_writers_arg
{
    bool slow_read;
    bool slow_write;
    _Atomic(size_t) nread;
    _Atomic(size_t) nwritten;
} test_multiple_readers_writers_arg_t;

static void* _read_z_thread(void* arg_)
{
    test_multiple_readers_writers_arg_t* arg = arg_;

    for (;;)
    {
        char c;

        if (arg->slow_read)
            sleep_msec(3);

        ssize_t n = read(pipefd[0], &c, sizeof(c));
        assert(n == 1);

        arg->nread++;

        if (c == '\0')
            break;

        assert(c == 'z');
    }

    return NULL;
}

static void* _write_z_thread(void* arg_)
{
    test_multiple_readers_writers_arg_t* arg = arg_;

    for (size_t i = 0; i < N; i++)
    {
        if (arg->slow_write)
            sleep_msec(3);

        char c = (i + 1 == N) ? '\0' : 'z';

        ssize_t n = write(pipefd[1], &c, 1);
        assert(n == 1);
        arg->nwritten++;
    }

    return NULL;
}

void test_multiple_readers_writers(bool slow_write, bool slow_read)
{
    const size_t NUM_THREADS = 16;
    pthread_t threads[NUM_THREADS];
    const char* msg1 = slow_write ? "slow-writer" : "fast-writer";
    const char* msg2 = slow_read ? "slow-reader" : "fast-reader";
    test_multiple_readers_writers_arg_t arg;

    printf("=== start test (%s: %s/%s)\n", __FUNCTION__, msg1, msg2);

    arg.nread = 0;
    arg.nwritten = 0;
    arg.slow_read = slow_read;
    arg.slow_write = slow_write;

    /* Create the pipe */
    assert(pipe2(pipefd, 0) == 0);
    assert(fcntl(pipefd[0], F_SETPIPE_SZ, 4096) == 0);
    assert(fcntl(pipefd[1], F_SETPIPE_SZ, 4096) == 0);

    /* Create the reader threads */
    for (size_t i = 0; i < NUM_THREADS / 2; i++)
    {
        if (pthread_create(&threads[i], NULL, _read_z_thread, &arg) != 0)
        {
            fprintf(stderr, "pthread_create() failed\n");
            abort();
        }
    }

    /* Create the writer threads */
    for (size_t i = NUM_THREADS / 2; i < NUM_THREADS; i++)
    {
        if (pthread_create(&threads[i], NULL, _write_z_thread, &arg) != 0)
        {
            fprintf(stderr, "pthread_create() failed\n");
            abort();
        }
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

    assert(arg.nread == arg.nwritten);
    assert(arg.nread == (NUM_THREADS / 2) * N);

    close(pipefd[0]);
    close(pipefd[1]);

    printf("=== passed test (%s: %s/%s)\n", __FUNCTION__, msg1, msg2);
}

/*
**==============================================================================
**
** main()
**
**==============================================================================
*/

int main(int argc, const char* argv[])
{
    /* test all combinations of fast/slow writers/readers */
    test_pipes(0, 0);
    test_pipes(0, 1);
    test_pipes(1, 0);
    test_pipes(1, 1);

    /* test whether pipe size can be determined through polling */
    test_pipe_size();

    /* test multiple readers/writers in all combinations of fast/slow */
    test_multiple_readers_writers(false, false);
    test_multiple_readers_writers(false, true);
    test_multiple_readers_writers(true, false);
    test_multiple_readers_writers(true, true);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
