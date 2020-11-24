// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <unistd.h>

#define WAKE_MAGIC 0x617eafc2e697492c

/* wake pipe */
static int _wakefds[2];

static pthread_once_t _create_wakefds_once = PTHREAD_ONCE_INIT;

static int _set_nonblock(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
        return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        return -1;

    return 0;
}

static void _create_wakefds(void)
{
    if (pipe(_wakefds) == -1)
        abort();

    if (_set_nonblock(_wakefds[0]) != 0)
        abort();

    if (_set_nonblock(_wakefds[1]) != 0)
        abort();
}

long libos_tcall_poll_wake(void)
{
    uint64_t x = WAKE_MAGIC;

    /* Create the wake pipe */
    pthread_once(&_create_wakefds_once, _create_wakefds);

    if (write(_wakefds[1], &x, sizeof(x)) != x)
        return -EINVAL;

    return 0;
}

long libos_tcall_poll(struct pollfd* lfds, unsigned long nfds, int timeout)
{
    long ret = 0;
    long r;
    struct pollfd* fds = NULL;

    /* Create the wake pipe */
    pthread_once(&_create_wakefds_once, _create_wakefds);

    /* Make a copy of the fds[] array and append the wake pipe */
    {
        if (!(fds = calloc(nfds + 1, sizeof(struct pollfd))))
        {
            ret = -ENOMEM;
            goto done;
        }

        if (lfds)
            memcpy(fds, lfds, nfds * sizeof(struct pollfd));

        /* watch for reads on the read-end of the wake pipe */
        fds[nfds].fd = _wakefds[0];
        fds[nfds].events = POLLIN;
    }

    /* Wait for events */
    if ((r = poll((struct pollfd*)fds, nfds + 1, timeout)) < 0)
        return -errno;

    /* Check whether there were any writes to the wake pipe */
    if (fds[nfds].revents & POLLIN)
    {
        uint64_t x;
        ssize_t n;

        /* consume all words written to the pipe */
        while ((n = read(_wakefds[0], &x, sizeof(x))) == sizeof(x))
        {
            if (x != WAKE_MAGIC)
            {
                ret = -EINVAL;
                goto done;
            }
        }

        if (n == -1 && errno != EWOULDBLOCK)
        {
            ret = -EINVAL;
            goto done;
        }

        /* don't return a value that includes this wake descriptor */
        r--;
    }

    /* Copy back the array */
    if (lfds)
        memcpy(lfds, fds, nfds * sizeof(struct pollfd));

    ret = r;

done:

    if (fds)
        free(fds);

    return ret;
}
