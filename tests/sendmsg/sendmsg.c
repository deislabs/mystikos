// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
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
    struct sockaddr_in addr;
    const int backlog = 10;
    int sock = -1;
    bool quit = false;

    /* Create the listener socket. */
    assert((lsock = socket(AF_INET, SOCK_STREAM, 0)) >= 0);

    {
        const int opt = 1;
        const socklen_t len = sizeof(opt);
        assert(setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &opt, len) == 0);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    assert(bind(lsock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    assert(listen(lsock, backlog) == 0);

    while (!quit)
    {
        ssize_t n;

        assert((sock = accept(lsock, NULL, NULL)) >= 0);

        for (;;)
        {
            struct msghdr msg = {0};
            struct iovec iov;
            uint8_t iov_buf[256];
            uint8_t msg_control_buf[256] = {0};

            memset(&msg, 0, sizeof(msg));
            iov.iov_base = iov_buf;
            iov.iov_len = sizeof(iov_buf);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = msg_control_buf;
            msg.msg_controllen = sizeof(msg_control_buf);

            if ((n = recvmsg(sock, &msg, 0)) < 0)
                assert("read() failed" == NULL);

            iov.iov_len = (typeof(iov.iov_len))n;

            if (n > 0)
            {
                if (n > 0 && msg.msg_iovlen == 1)
                {
                    const char* str = (const char*)msg.msg_iov[0].iov_base;

                    if (strncmp(str, "quit", msg.msg_iov[0].iov_len) == 0)
                    {
                        quit = true;
                        // Before quit, check if recvmsg returns EAGAIN
                        // for nonblocking socks.
                        fcntl(sock, F_SETFL, 04002);
                        int r = recvmsg(sock, &msg, 2);
                        assert(r == -1 && errno == EAGAIN);
                        break;
                    }
                }

                assert(sendmsg(sock, &msg, 0) == n);
            }
        }
    }

    _sleep_msec(100);
    assert(close(sock) == 0);
    assert(close(lsock) == 0);

    return NULL;
}

static void* _cli_thread_func(void* arg)
{
    int sock;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    assert((sock = socket(AF_INET, SOCK_STREAM, 0)) >= 0);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    assert(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0);

    /* send/receive a messsage to/from the server */
    {
        static const uint8_t iov0[] = {'t', 'h', 'i', 's', ' '};
        static const uint8_t iov1[] = {'i', 's', ' '};
        static const uint8_t iov2[] = {'a', ' '};
        static const uint8_t iov3[] = {'t', 'e', 's', 't', '\0'};

        static const struct iovec iov[] = {
            {
                .iov_base = (void*)iov0,
                .iov_len = sizeof(iov0),
            },
            {
                .iov_base = (void*)iov1,
                .iov_len = sizeof(iov1),
            },
            {
                .iov_base = (void*)iov2,
                .iov_len = sizeof(iov2),
            },
            {
                .iov_base = (void*)iov3,
                .iov_len = sizeof(iov3),
            },
        };
        static const size_t iovlen = sizeof(iov) / sizeof(iov[0]);
        ssize_t total_iov_size = 0;
        uint8_t iov0_buf[256];
        uint8_t iov1_buf[256];
        uint8_t iov2_buf[256];
        uint8_t iov3_buf[256];
        struct iovec iov_buf[4];
        struct msghdr msg_recv;
        struct msghdr msg_send;

        memset(&msg_send, 0, sizeof(msg_send));
        memset(&msg_recv, 0, sizeof(msg_recv));

        for (size_t i = 0; i < iovlen; i++)
            total_iov_size += (ssize_t)iov[i].iov_len;

        msg_send.msg_iov = (struct iovec*)iov;
        msg_send.msg_iovlen = 4;
        assert(sendmsg(sock, &msg_send, 0) == total_iov_size);

        {
            iov_buf[0].iov_base = iov0_buf;
            iov_buf[0].iov_len = sizeof(iov0);
            iov_buf[1].iov_base = iov1_buf;
            iov_buf[1].iov_len = sizeof(iov1);
            iov_buf[2].iov_base = iov2_buf;
            iov_buf[2].iov_len = sizeof(iov2);
            iov_buf[3].iov_base = iov3_buf;
            iov_buf[3].iov_len = sizeof(iov3);

            memset(&msg_recv, 0, sizeof(msg_recv));
            msg_recv.msg_iov = iov_buf;
            msg_recv.msg_iovlen = (typeof(msg_recv.msg_iovlen))iovlen;
            assert(recvmsg(sock, &msg_recv, 0) == total_iov_size);
        }

        {
            assert(msg_send.msg_iovlen == msg_send.msg_iovlen);
            typedef typeof(msg_send.msg_iovlen) msg_iovlen_type;

            for (msg_iovlen_type i = 0; i < msg_send.msg_iovlen; i++)
            {
                const struct iovec* p = &msg_send.msg_iov[i];
                const struct iovec* q = &msg_send.msg_iov[i];

                assert(p->iov_len == q->iov_len);
                assert(p->iov_base != NULL);
                assert(q->iov_base != NULL);
                assert(memcmp(p->iov_base, q->iov_base, p->iov_len) == 0);
            }
        }
    }

    /* send "done" message the server */
    {
        static const uint8_t iov0[] = {'q', 'u', 'i', 't', '\0'};

        static const struct iovec iov[] = {
            {
                .iov_base = (void*)iov0,
                .iov_len = sizeof(iov0),
            },
        };
        static const size_t iovlen = sizeof(iov) / sizeof(iov[0]);
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));

        msg.msg_iov = (struct iovec*)iov;
        msg.msg_iovlen = (typeof(msg.msg_iovlen))iovlen;

        ssize_t m = sendmsg(sock, &msg, 0);
        assert(m == sizeof(iov0));
    }

    // Be nasty here. Leave the connection open.
    // close(sock);

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
