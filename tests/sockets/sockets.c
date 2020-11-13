// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static const uint16_t port = 12345;

static const char alpha[] = "abcdefghijklmnopqrstuvwxyz";

static void _sleep_msec(uint32_t msec)
{
    struct timespec ts;
    ts.tv_sec = (uint64_t)msec / 1000;
    ts.tv_nsec = ((int64_t)msec % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

typedef struct args
{
    int domain;
    const char* path;
} args_t;

static void* _srv_thread_func(void* arg)
{
    args_t* args = (args_t*)arg;
    int lsock;
    int r;

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
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        assert(bind(lsock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    }
    else if (args->domain == AF_UNIX)
    {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strcpy(addr.sun_path, args->path);

        struct stat buf;

        assert(fchmod(lsock, 0000) == 0);
        assert(fstat(lsock, &buf) == 0);
        assert((buf.st_mode & 0x000001ff) == 0000);

        assert(fchmod(lsock, 0777) == 0);
        assert(fstat(lsock, &buf) == 0);
        assert((buf.st_mode & 0x000001ff) == 0777);

        assert(bind(lsock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    }
    else
    {
        assert(0);
    }

    assert(listen(lsock, 10) == 0);

    for (;;)
    {
        int sock;

        printf("server: waiting for connection...\n");
        sock = accept(lsock, (struct sockaddr*)NULL, NULL);
        assert(sock > 0);
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

    assert((sock = socket(args->domain, SOCK_STREAM, 0)) >= 0);

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
        strcpy(addr.sun_path, args->path);
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
        n = recv(sock, buf, sizeof(buf), 0);

        if (n == 0)
            break;

        assert(n > 0);

        printf("buf{%s}\n", buf);
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

    assert(pthread_create(&srv_thread, NULL, _srv_thread_func, args) == 0);
    _sleep_msec(100);
    assert(pthread_create(&cli_thread, NULL, _cli_thread_func, args) == 0);

    pthread_join(cli_thread, NULL);
    pthread_join(srv_thread, NULL);

    printf("=== passed test (test_sockets: domain=%d)\n", args->domain);
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <uds-path>\n", argv[0]);
        exit(1);
    }

    args_t inet_args = {AF_INET, NULL};
    args_t unix_args = {AF_UNIX, argv[1]};

    test_sockets(&inet_args);
    test_sockets(&unix_args);

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
