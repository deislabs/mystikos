// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <sys/select.h>

#include <myst/eraise.h>
#include <myst/syscall.h>

#define POLLIN_SET (POLLRDNORM | POLLRDBAND | POLLIN | POLLHUP | POLLERR)
#define POLLOUT_SET (POLLWRBAND | POLLWRNORM | POLLOUT | POLLERR)
#define POLLEX_SET (POLLPRI | POLLERR | POLLHUP | POLLRDHUP)

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
            fds->data[i].events |= events;
            /* success */
            goto done;
        }
    }

    /* if the array is exhausted */
    if (fds->size == MYST_COUNTOF(fds->data))
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

long myst_syscall_select(
    int nfds,
    fd_set* readfds,
    fd_set* writefds,
    fd_set* exceptfds,
    struct timeval* timeout)
{
    long ret = 0;
    int num_ready = 0;
    int poll_timeout = -1;
    struct locals
    {
        poll_fds_t fds;
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    memset(&locals->fds, 0, sizeof(locals->fds));

    if (timeout)
    {
        poll_timeout = (int)timeout->tv_sec * 1000;
        poll_timeout += (int)(timeout->tv_usec / 1000);
    }

    if (readfds)
    {
        const short events = POLLIN_SET;
        ECHECK(_fdset_to_fds(&locals->fds, events, readfds, nfds));
    }

    if (writefds)
    {
        const short events = POLLOUT_SET;
        ECHECK(_fdset_to_fds(&locals->fds, events, writefds, nfds));
    }

    if (exceptfds)
    {
        const short events = POLLEX_SET;
        ECHECK(_fdset_to_fds(&locals->fds, events, exceptfds, nfds));
    }

    ECHECK(myst_syscall_poll(locals->fds.data, locals->fds.size, poll_timeout));

    if (readfds)
    {
        short events = POLLIN_SET;
        int n;

        FD_ZERO(readfds);

        if ((n = _fds_to_fdset(&locals->fds, events, readfds)) > num_ready)
            num_ready += n;
    }

    if (writefds)
    {
        short events = POLLOUT_SET;
        int n;

        FD_ZERO(writefds);

        if ((n = _fds_to_fdset(&locals->fds, events, writefds)) > num_ready)
            num_ready += n;
    }

    if (exceptfds)
    {
        short events = POLLEX_SET;
        int n;

        FD_ZERO(exceptfds);

        if ((n = _fds_to_fdset(&locals->fds, events, exceptfds)) > num_ready)
            num_ready += n;
    }

    ret = num_ready;

done:

    if (locals)
        free(locals);

    return ret;
}
