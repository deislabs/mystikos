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
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_SIZE 13

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

typedef struct _client
{
    int sock;
    uint8_t* data;
    size_t size;
} client_t;

#define MAX_CLIENTS 8

typedef struct _clients
{
    client_t data[MAX_CLIENTS];
    size_t size;
} clients_t;

client_t* find_client(clients_t* clients, int sock)
{
    for (size_t i = 0; i < clients->size; i++)
    {
        if (clients->data[i].sock == sock)
            return &clients->data[i];
    }

    /* Not found */
    return NULL;
}

int client_append(client_t* client, const void* data, size_t size)
{
    size_t n = client->size + size;

    if (!(client->data = realloc(client->data, n)))
        return -1;

    memcpy(client->data + client->size, data, size);
    client->size = n;

    return 0;
}

int client_remove_leading(client_t* client, size_t size)
{
    if (size > client->size)
        return -1;

    size_t n = client->size - size;
    memcpy(client->data, client->data + size, n);
    client->size -= size;

    return 0;
}

static int set_blocking(int sock, bool blocking)
{
    int flags;

    if ((flags = fcntl(sock, F_GETFL, 0)) == -1)
        return -1;

    if (blocking)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    if (fcntl(sock, F_SETFL, flags) == -1)
        return -1;

    return 0;
}

static int add_events(int epfd, int sock, uint32_t events)
{
    int r;
    struct epoll_event ev = {.data.fd = sock, .events = events};
    return epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
}

static int mod_events(int epfd, int sock, uint32_t events)
{
    int r;
    struct epoll_event ev = {.data.fd = sock, .events = events};
    return epoll_ctl(epfd, EPOLL_CTL_MOD, sock, &ev);
}

static int del_events(int epfd, int sock)
{
    int r;
    struct epoll_event ev = {.data.fd = sock, .events = 0};
    return epoll_ctl(epfd, EPOLL_CTL_DEL, sock, &ev);
}

void run_server(uint16_t port, size_t num_clients)
{
    int lsock;
    bool quit = false;
    clients_t clients;
    size_t num_disconnects = 0;
    int epfd;

    assert((epfd = epoll_create1(0)) >= 0);

    memset(&clients, 0, sizeof(clients));

    if ((lsock = create_listener_socket(port)) == -1)
    {
        assert("create_listener_socket() failed" == NULL);
    }

    /* Watch for read events on the lsock socket (i.e., connects). */
    assert(add_events(epfd, lsock, EPOLLIN) == 0);

    while (!quit)
    {
        client_t* client;
        const static int maxevents = MAX_CLIENTS;
        struct epoll_event events[maxevents];
        int timeout = 1000;

        /* Wait for events. */
        printf("wait for events...\n");
        int n = epoll_wait(epfd, events, maxevents, timeout);
        assert(n >= 0);

        for (size_t i = 0; i < n; i++)
        {
            struct epoll_event* event = &events[i];

            if (event->events == 0)
                continue;

            /* Handle client connection. */
            if (event->data.fd == lsock)
            {
                if ((event->events & EPOLLIN))
                {
                    int sock;

                    if ((sock = accept(lsock, NULL, NULL)) < 0)
                        assert("accept() failed" == NULL);

                    printf("accepted connection\n");

                    client_t client;
                    client.sock = sock;
                    client.data = NULL;
                    client.size = 0;
                    clients.data[clients.size++] = client;

                    set_blocking(sock, false);

                    assert(add_events(epfd, sock, EPOLLIN) == 0);

                    printf("client %d connect\n", sock);
                    fflush(stdout);
                }
                else
                {
                    assert(false);
                }

                continue;
            }

            /* Find the client for this event. */
            assert((client = find_client(&clients, event->data.fd)));

            /* Handle client input. */
            if ((event->events & EPOLLIN))
            {
                /* Read until EAGAIN is encountered. */
                for (;;)
                {
                    uint8_t buf[BUFFER_SIZE];
                    ssize_t n;

                    errno = 0;

                    n = recv(client->sock, buf, sizeof(buf), 0);
                    if (n > 0)
                    {
                        printf("client %d input: %zd bytes\n", client->sock, n);
                        fflush(stdout);

                        assert(client_append(client, buf, n) == 0);
                        uint32_t events = EPOLLIN | EPOLLOUT;
                        assert(mod_events(epfd, client->sock, events) == 0);
                    }
                    else if (n == 0)
                    {
                        printf("client %d disconnect\n", client->sock);
                        fflush(stdout);

                        /* Client disconnect. */
                        // Be nasty here: keep the closed sock in epoll FD list.
                        // del_events(epfd, client->sock);
                        close(client->sock);
                        client->sock = -1;

                        num_disconnects++;

                        if (num_disconnects == num_clients)
                        {
                            quit = true;
                        }
                        break;
                    }
                    else if (errno == EAGAIN)
                    {
                        break;
                    }
                    else
                    {
                        assert(false);
                    }
                }

                if (quit)
                    break;
            }

            /* Handle client output */
            if (client->sock != -1 && (event->events & EPOLLOUT))
            {
                /* Write until output is exhausted or EAGAIN encountered. */
                for (;;)
                {
                    ssize_t n;

                    assert(client->size > 0);

                    errno = 0;

                    /* Send data to client. */
                    n = send(client->sock, client->data, client->size, 0);

                    if (n > 0)
                    {
                        printf(
                            "client %d output: %zd bytes\n", client->sock, n);
                        fflush(stdout);

                        assert(client_remove_leading(client, n) == 0);

                        if (client->size == 0)
                        {
                            uint32_t events = EPOLLIN;
                            mod_events(epfd, event->data.fd, events);
                            break;
                        }
                    }
                    else if (n == -1 && errno == EAGAIN)
                    {
                        break;
                    }
                    else
                    {
                        assert(false);
                    }
                }
            }
        }
    }

    close(lsock);
    close(epfd);
}

int main(int argc, const char* argv[])
{
    run_server(12345, 1);

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
