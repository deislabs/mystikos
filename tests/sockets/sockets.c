// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static const uint16_t port = 12345;

static bool _read_one_byte_at_at_time;

static const char alpha[] = "abcdefghijklmnopqrstuvwxyz";

static pthread_barrier_t bar;

typedef struct args
{
    int domain;
    const char* path;
} args_t;

static ssize_t _recvn(int fd, void* data_in, size_t size, int flags)
{
    ssize_t ret = 0;
    uint8_t* p = (uint8_t*)data_in;
    size_t r = size;
    size_t m = 0;

    while (r > 0)
    {
        ssize_t n = recv(fd, p, r, flags);

        if (n == 0)
            break;

        if (n < 0)
        {
            ret = -1;
            goto done;
        }

        p += n;
        r -= (size_t)n;
        m += (size_t)n;
    }

    ret = m;

done:

    return ret;
}

/*
**==============================================================================
**
** test_sockets()
**
**==============================================================================
*/

static void* _srv_thread_func(void* arg)
{
    args_t* args = (args_t*)arg;
    int lsock;
    int r;
    struct sockaddr* common_addr;
    struct sockaddr_in addr_in;
    struct sockaddr_un addr_un;

    (void)arg;

    assert((lsock = socket(args->domain, SOCK_STREAM, 0)) >= 0);

    /* reuse the server address */
    {
        const int opt = 1;
        const socklen_t len = sizeof(opt);
        r = setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, len);
        assert(r == 0);
    }

    if (args->domain == AF_INET)
    {
        memset(&addr_in, 0, sizeof(addr_in));
        addr_in.sin_family = AF_INET;
        addr_in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr_in.sin_port = htons(port);
        assert(bind(lsock, (struct sockaddr*)&addr_in, sizeof(addr_in)) == 0);
        common_addr = &addr_in;
    }
    else if (args->domain == AF_UNIX)
    {
        memset(&addr_un, 0, sizeof(addr_un));
        addr_un.sun_family = AF_UNIX;
        *addr_un.sun_path = '\0';
        if (args->path[0])
            strncat(addr_un.sun_path, args->path, sizeof(addr_un.sun_path) - 1);
        else
            memcpy(addr_un.sun_path, args->path, sizeof(addr_un.sun_path) - 1);

        struct stat buf;

        assert(fchmod(lsock, 0000) == 0);
        assert(fstat(lsock, &buf) == 0);
        assert((buf.st_mode & 0x000001ff) == 0000);

        assert(fchmod(lsock, 0777) == 0);
        assert(fstat(lsock, &buf) == 0);
        assert((buf.st_mode & 0x000001ff) == 0777);

        assert(bind(lsock, (struct sockaddr*)&addr_un, sizeof(addr_un)) == 0);
        // Test EINVAL if socket is already bound
        assert(
            bind(lsock, (struct sockaddr*)&addr_un, sizeof(addr_un)) != 0 &&
            errno == EINVAL);
        common_addr = &addr_un;
    }
    else
    {
        assert(0);
    }

    assert(listen(lsock, 10) == 0);

    // Test EADDRINUSE if a server socket is listening on the same address
    {
        int sock2 = socket(args->domain, SOCK_STREAM, 0);
        assert(
            bind(sock2, common_addr, sizeof(struct sockaddr)) != 0 &&
            errno == EADDRINUSE);
    }

    // client can now proceed to connect()
    pthread_barrier_wait(&bar);

    for (;;)
    {
        int sock;

        printf("server: waiting for connection...\n");

        if (args->domain == AF_INET)
        {
            struct sockaddr_in addr;
            socklen_t addrlen = sizeof(addr);
            sock = accept4(lsock, (struct sockaddr*)NULL, &addrlen, 0);
            assert(sock > 0);

            printf("addrlen=%u/%zu\n", addrlen, sizeof(addr));
        }
        else
        {
            struct sockaddr_un addr;
            socklen_t addrlen = sizeof(addr);
            sock = accept4(lsock, (struct sockaddr*)&addr, &addrlen, 0);
            assert(sock > 0);
        }

        printf("server: accepted connection: %d\n", sock);

        printf("server: send\n");
        ssize_t n = send(sock, alpha, strlen(alpha), 0);
        assert((size_t)n == strlen(alpha));
        close(sock);
        break;
    }

    close(lsock);
    printf("server: finished\n");

    return NULL;
}

static void* _cli_thread_func(void* arg)
{
    args_t* args = (args_t*)arg;
    int sock = 0;
    ssize_t n = 0;

    assert((sock = socket(args->domain, SOCK_STREAM | SOCK_CLOEXEC, 0)) >= 0);

    /* test dup() */
    {
        int tmp_sock = dup(sock);
        assert(tmp_sock >= 0);
        assert(close(sock) == 0);
        sock = tmp_sock;
    }

    // wait till server thread is listening on address
    pthread_barrier_wait(&bar);
    if (args->domain == AF_INET)
    {
        printf("client: connect\n");
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        assert(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) >= 0);
    }
    else if (args->domain == AF_UNIX)
    {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        *addr.sun_path = '\0';
        if (args->path[0])
            strncat(addr.sun_path, args->path, sizeof(addr.sun_path) - 1);
        else
            memcpy(addr.sun_path, args->path, sizeof(addr.sun_path) - 1);

        assert(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) >= 0);
    }
    else
    {
        assert(0);
    }

    for (;;)
    {
        static char buf[1024];

        printf("client: recv\n");

        if (_read_one_byte_at_at_time)
        {
            n = 0;

            memset(buf, 0, sizeof(buf));

            for (ssize_t i = 0; i < strlen(alpha); i++)
            {
                ssize_t r = recv(sock, &buf[i], 1, 0);

                if (r == 0)
                    break;

                assert(r == 1);
                n++;
            }
        }
        else
        {
            n = _recvn(sock, buf, sizeof(buf), 0);
        }

        if (n == 0)
            break;

        assert(n > 0);

        printf("buf{%s} n=%zd\n", buf, n);
        assert(n == strlen(alpha));
        assert(memcmp(buf, alpha, n) == 0);
    }

    close(sock);

    return NULL;
}

void test_sockets(args_t* args)
{
    pthread_t srv_thread;
    pthread_t cli_thread;

    pthread_barrier_init(&bar, NULL, 2);

    assert(pthread_create(&srv_thread, NULL, _srv_thread_func, args) == 0);
    assert(pthread_create(&cli_thread, NULL, _cli_thread_func, args) == 0);

    pthread_join(cli_thread, NULL);
    pthread_join(srv_thread, NULL);

    pthread_barrier_destroy(&bar);

    printf("=== passed test (test_sockets: domain=%d)\n", args->domain);
}

/*
**==============================================================================
**
** test_socketpair()
**
**==============================================================================
*/

static void test_socketpair(void)
{
    int sv[2];
    ssize_t n;
    char buf[sizeof(alpha)];

    assert(socketpair(AF_LOCAL, SOCK_STREAM, 0, sv) == 0);
    assert(write(sv[0], alpha, sizeof(alpha)) == sizeof(alpha));

    int nread = -1;
    assert(ioctl(sv[1], FIONREAD, (unsigned long*)&nread) == 0);
    assert(nread > 0);
    assert(nread == sizeof(alpha));

    assert(read(sv[1], buf, sizeof(buf)) == sizeof(buf));
    assert(memcmp(buf, alpha, sizeof(buf)) == 0);

    assert(close(sv[0]) == 0);
    assert(close(sv[1]) == 0);
}

/*
**==============================================================================
**
** test_socketpair_nonblock()
**
**==============================================================================
*/

int get_events(int fd)
{
    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLIN | POLLOUT;

    int ret = poll(fds, 1, 0);

    if (ret == 1)
        return fds[0].revents;

    return ret;
}

bool can_read(int fd)
{
    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    int ret = poll(fds, 1, 0);
    return (ret == 1) && (fds[0].revents & POLLIN);
}

bool can_write(int fd)
{
    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLOUT;
    int ret = poll(fds, 1, 0);
    return (ret == 1) && (fds[0].revents & POLLOUT);
}

static void _fill_sock_buf(int sockfd)
{
    char buf[1024];
    ssize_t n;

    while ((n = send(sockfd, buf, sizeof(buf), 0)) > 0)
        ;

    assert(n == -1 && errno == EAGAIN);
}

static void _empty_sock_buf(int sockfd)
{
    char buf[1024];
    ssize_t n;

    while ((n = recv(sockfd, buf, sizeof(buf), 0)) > 0)
        ;

    assert(n == -1 && errno == EAGAIN);
}

static void test_socketpair_nonblock(void)
{
    pthread_t srv_thread;
    pthread_t cli_thread;
    int sv[2];

    assert(socketpair(AF_LOCAL, SOCK_STREAM, 0, sv) == 0);

    int size = 0;
    socklen_t len = sizeof(size);
    assert(getsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, (void*)&size, &len) == 0);
    assert(size > 0);

    size = 1;
    len = sizeof(size);
    assert(setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, (void*)&size, len) == 0);
    assert(size > 0);

    size = 0;
    len = sizeof(size);
    assert(getsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, (void*)&size, &len) == 0);
    assert(size > 1);

    /* make sockets non-blocking */
    {
        int val = 1;
        assert(ioctl(sv[0], FIONBIO, &val) == 0);
        assert(ioctl(sv[1], FIONBIO, &val) == 0);
    }

    /* check events */
    assert(can_write(sv[0]));
    assert(!can_read(sv[0]));
    assert(can_write(sv[1]));
    assert(!can_read(sv[1]));

    _fill_sock_buf(sv[0]);

    /* check events */
    assert(!can_write(sv[0]));
    assert(!can_read(sv[0]));
    assert(can_write(sv[1]));
    assert(can_read(sv[1]));

    _empty_sock_buf(sv[1]);

    /* check events */
    assert(can_write(sv[0]));
    assert(!can_read(sv[0]));
    assert(can_write(sv[1]));
    assert(!can_read(sv[1]));

    /* check events */
    assert(can_write(sv[1]));
    assert(!can_read(sv[1]));
    assert(can_write(sv[0]));
    assert(!can_read(sv[0]));

    _fill_sock_buf(sv[1]);

    /* check events */
    assert(!can_write(sv[1]));
    assert(!can_read(sv[1]));
    assert(can_write(sv[0]));
    assert(can_read(sv[0]));

    _empty_sock_buf(sv[0]);

    /* check events */
    assert(can_write(sv[1]));
    assert(!can_read(sv[1]));
    assert(can_write(sv[0]));
    assert(!can_read(sv[0]));

    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    args_t inet_args = {AF_INET, NULL};
    test_sockets(&inet_args);

    args_t unix_args = {AF_UNIX, "/tmp/uds"};
    _read_one_byte_at_at_time = false;
    test_sockets(&unix_args);

    unlink("/tmp/uds");

    _read_one_byte_at_at_time = true;
    test_sockets(&unix_args);

    /* Test Abstract Namespace addresses for UDS */
    unix_args.path = "\0sockfoo";
    _read_one_byte_at_at_time = false;
    test_sockets(&unix_args);

    test_socketpair();

    test_socketpair_nonblock();

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
