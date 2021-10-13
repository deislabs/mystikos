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
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

int create_listener_socket(uint16_t port)
{
    int ret = -1;
    int sock = -1;
    const int opt = 1;
    const socklen_t n = sizeof(opt);
    struct sockaddr_in addr;
    const int backlog = 10;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        goto done;

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, n) != 0)
        goto done;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        goto done;

    if (listen(sock, backlog) != 0)
        goto done;

    ret = sock;
    sock = -1;

done:

    if (sock != -1)
        close(sock);

    return ret;
}

void run_server(uint16_t port)
{
    int lsock;
    int sock;
    ssize_t count = BIG_FILE_SIZE;
    int fd;
    ssize_t total = 0;
    size_t sendbuf_size = 64 * 1024;
    off_t off = 0;

    /* open the file to be sent */
    if ((fd = open("/bigfile", O_RDONLY)) < 0)
        assert("open() failed" == NULL);

    if ((lsock = create_listener_socket(port)) == -1)
        assert("create_listener_socket() failed" == NULL);

    /* wait for a client to connect */
    if ((sock = accept(lsock, NULL, NULL)) < 0)
        assert("accept() failed" == NULL);

    /* set client socket as non-blocking */
    {
        int opt = 1;

        if (ioctl(sock, FIONBIO, &opt) != 0)
            assert("ioctl() failed" == NULL);
    }

    /* set the send buffer size */
    {
        size_t arg = sendbuf_size;
        socklen_t optlen = sizeof(arg);

        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &arg, optlen) != 0)
            assert("getsockopt() failed" == NULL);
    }

    /* get the send buffer size */
    {
        int arg = 0;
        socklen_t optlen = sizeof(arg);

        if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &arg, &optlen) != 0)
            assert("getsockopt() failed" == NULL);

        printf("arg=%d\n", arg);
        printf("sendbuf_size=%ld\n", sendbuf_size);
        assert(arg == sendbuf_size * 2);
    }

    /* while there are more bytes to write */
    while (count > 0)
    {
        struct pollfd fds[1];

        /* send the file */
        ssize_t n = sendfile(sock, fd, &off, count);

        if (n < 0 && errno == EAGAIN)
        {
            printf("=== server write encountered EAGAIN\n");
            /* wait for client socket to be write enabled */
            fds[0].fd = sock;
            fds[0].events = POLLOUT;
            int r = poll(fds, 1, -1);
            assert(r > 0);
        }
        else
        {
            printf("=== server sent %zd bytes\n", n);
            count -= n;
            total += n;
        }
    }

    assert(total == BIG_FILE_SIZE);
    printf("=== server sent %zu bytes\n", total);

    close(lsock);
    close(sock);
    close(fd);
}
