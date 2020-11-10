// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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

static void* _srv_thread_func(void* arg)
{
    int lsock;
    int r;
    struct sockaddr_in addr;

    (void)arg;

    assert((lsock = socket(AF_INET, SOCK_STREAM, 0)) >= 0);

    /* reuse the server address */
    {
        const int opt = 1;
        const socklen_t len = sizeof(opt);
        r = setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, len);
        assert(r == 0);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    assert(bind(lsock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
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
    int sock = 0;
    ssize_t n = 0;
    struct sockaddr_in addr = {0};

    assert((sock = socket(AF_INET, SOCK_STREAM, 0)) >= 0);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    int retries = 0;
    static const int max_retries = 400;

    printf("client: connect\n");
    assert(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) >= 0);

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

int main(int argc, const char* argv[])
{
    pthread_t srv_thread;
    pthread_t cli_thread;

    assert(pthread_create(&srv_thread, NULL, _srv_thread_func, NULL) == 0);
    _sleep_msec(100);
    assert(pthread_create(&cli_thread, NULL, _cli_thread_func, NULL) == 0);

    pthread_join(cli_thread, NULL);
    pthread_join(srv_thread, NULL);

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
