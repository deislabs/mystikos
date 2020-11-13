// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>

#include <libos/defs.h>
#include <libos/eraise.h>
#include <libos/fdops.h>
#include <libos/fdtable.h>
#include <libos/sockdev.h>
#include <libos/syscall.h>
#include <libos/tcall.h>

typedef struct _poll_fds
{
    nfds_t size;
    struct pollfd data[FD_SETSIZE];
} poll_fds_t;

int _update_fds(poll_fds_t* fds, int fd, short events)
{
    int ret = 0;
    nfds_t i;

    /* if the fd is already in the array, update it */
    for (i = 0; i < fds->size; i++)
    {
        if (fds->data[i].fd == fd)
        {
            fds->data[i].events = events;
            /* success */
            goto done;
        }
    }

    /* if the array is exhausted */
    if (fds->size == LIBOS_COUNTOF(fds->data))
        ERAISE(-EINVAL);

    /* append the new element */
    fds->data[fds->size].fd = fd;
    fds->data[fds->size].events = events;
    fds->data[fds->size].revents = 0;
    fds->size++;

done:
    return ret;
}

int _fdset_to_fds(poll_fds_t* fds, short events, fd_set* set, int nfds)
{
    int ret = 0;
    int fd;

    for (fd = 0; fd < nfds; fd++)
    {
        if (FD_ISSET(fd, set))
            ECHECK(_update_fds(fds, fd, events));
    }

done:
    return ret;
}

int _fds_to_fdset(poll_fds_t* fds, short revents, fd_set* set)
{
    int num_ready = 0;
    nfds_t i;

    for (i = 0; i < fds->size; i++)
    {
        const struct pollfd* p = &fds->data[i];

        if ((p->revents & revents))
        {
            FD_SET(p->fd, set);
            num_ready++;
        }
    }

    return num_ready;
}

long libos_syscall_select(
    int nfds,
    fd_set* readfds,
    fd_set* writefds,
    fd_set* exceptfds,
    struct timeval* timeout)
{
    long ret = 0;
    int num_ready = 0;
    poll_fds_t fds = {0};
    int poll_timeout = -1;

    if (timeout)
    {
        poll_timeout = (int)timeout->tv_sec * 1000;
        poll_timeout += (int)(timeout->tv_usec / 1000);
    }

    if (readfds)
    {
        const short events = POLLIN | POLLRDNORM | POLLRDBAND;
        ECHECK(_fdset_to_fds(&fds, events, readfds, nfds));
    }

    if (writefds)
    {
        const short events = POLLOUT | POLLWRNORM | POLLWRBAND;
        ECHECK(_fdset_to_fds(&fds, events, writefds, nfds));
    }

    if (exceptfds)
    {
        const short events = POLLERR | POLLHUP | POLLRDHUP;
        ECHECK(_fdset_to_fds(&fds, events, exceptfds, nfds));
    }

    ECHECK(libos_syscall_poll(fds.data, fds.size, poll_timeout));

    if (readfds)
        FD_ZERO(readfds);

    if (writefds)
        FD_ZERO(writefds);

    if (exceptfds)
        FD_ZERO(exceptfds);

    if (readfds)
    {
        short events = POLLIN | POLLRDNORM | POLLRDBAND;
        int n;

        if ((n = _fds_to_fdset(&fds, events, readfds)) > num_ready)
            num_ready += n;
    }

    if (writefds)
    {
        short events = POLLOUT | POLLWRNORM | POLLWRBAND;
        int n;

        if ((n = _fds_to_fdset(&fds, events, writefds)) > num_ready)
            num_ready += n;
    }

    if (exceptfds)
    {
        short events = POLLERR | POLLHUP | POLLRDHUP;
        int n;

        if ((n = _fds_to_fdset(&fds, events, exceptfds)) > num_ready)
            num_ready += n;
    }

    ret = num_ready;

done:

    return ret;
}
