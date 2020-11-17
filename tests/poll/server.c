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

#define MAX_CLIENTS 1024

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

#define MAX_FDS 1024

static int add_events(struct pollfd* fds, size_t* nfds, int sock, short events)
{
    for (size_t i = 0; i < *nfds; i++)
    {
        if (fds[i].fd == sock)
        {
            fds[i].events |= events;
            return 0;
        }
    }

    if (*nfds == MAX_FDS)
        return -1;

    fds[*nfds].fd = sock;
    fds[*nfds].events = events;
    fds[*nfds].revents = 0;
    (*nfds)++;

    return 0;
}

static int remove_events(
    struct pollfd* fds,
    size_t* nfds,
    int sock,
    short events)
{
    for (size_t i = 0; i < *nfds; i++)
    {
        if (fds[i].fd == sock)
        {
            fds[i].events &= ~events;

            if (fds[i].events == 0)
            {
                /* if not the last elements */
                if (i + 1 != *nfds)
                    memmove(&fds[i], &fds[i + 1], *nfds - i - 1);

                (*nfds)--;
            }
            return 0;
        }
    }

    return 0;
}

void run_server(uint16_t port, size_t num_clients)
{
    int lsock;
    bool quit = false;
    clients_t clients;
    size_t num_disconnects = 0;
    struct pollfd fds[MAX_FDS];
    size_t nfds = 0;

    memset(&clients, 0, sizeof(clients));

    if ((lsock = create_listener_socket(port)) == -1)
    {
        assert("create_listener_socket() failed" == NULL);
    }

    /* Watch for read events on the lsock socket (i.e., connects). */
    fds[nfds].fd = lsock;
    fds[nfds].events = POLLIN;
    nfds++;

    while (!quit)
    {
        client_t* client;

        /* Wait for events. */
        int r = poll(fds, nfds, -1);
        assert(r > 0);

        for (size_t i = 0; i < nfds; i++)
        {
            struct pollfd* event = &fds[i];

            if (event->revents == 0)
                continue;

            /* Handle client connection. */
            if (event->fd == lsock)
            {
                if ((event->revents & POLLIN))
                {
                    int sock;

                    if ((sock = accept(lsock, NULL, NULL)) < 0)
                        assert("accept() failed" == NULL);

                    client_t client;
                    client.sock = sock;
                    client.data = NULL;
                    client.size = 0;
                    clients.data[clients.size++] = client;

                    set_blocking(sock, false);

                    assert(add_events(fds, &nfds, sock, POLLIN) == 0);

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
            assert((client = find_client(&clients, event->fd)));

            /* Handle client input. */
            if ((event->events & POLLIN))
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
                        assert(
                            add_events(fds, &nfds, client->sock, POLLOUT) == 0);
                    }
                    else if (n == 0)
                    {
                        printf("client %d disconnect\n", client->sock);
                        fflush(stdout);

                        /* Client disconnect. */
                        const short events = POLLIN | POLLOUT;
                        remove_events(fds, &nfds, client->sock, events);
                        close(client->sock);

                        num_disconnects++;

                        if (num_disconnects == num_clients)
                        {
                            quit = true;
                            break;
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

            /* Handle client input. */
            if ((event->events & POLLOUT))
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
                            remove_events(fds, &nfds, event->fd, POLLOUT);
                            break;
                        }
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
            }
        }
    }

    close(lsock);
}
