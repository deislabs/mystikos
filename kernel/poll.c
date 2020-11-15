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

long _poll_kernel(struct pollfd* fds, nfds_t nfds)
{
    long ret = 0;
    libos_fdtable_t* fdtable;
    long total = 0;

    if (!(fdtable = libos_fdtable_current()))
        ERAISE(-ENOSYS);

    for (nfds_t i = 0; i < nfds; i++)
    {
        libos_fdtable_type_t type;
        libos_fdops_t* fdops;
        void* object;
        int events;

        fds[i].revents = 0;

        /* get the device for this file descriptor */
        ECHECK(libos_fdtable_get_any(
            fdtable, fds[i].fd, &type, (void**)&fdops, (void**)&object));

        if ((events = (*fdops->fd_get_events)(fdops, object)) >= 0)
        {
            fds[i].revents = events;

            if (events)
                total++;
        }
        else if (events != -ENOTSUP)
        {
            ERAISE(-EINVAL);
        }
    }

    ret = total;

done:
    return ret;
}

long libos_syscall_poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    long ret = 0;
    libos_fdtable_t* fdtable;
    struct pollfd* tfds = NULL; /* target file descriptors */
    struct pollfd* kfds = NULL; /* kernel file descriptors */
    nfds_t tnfds = 0; /* number of target file descriptors */
    nfds_t knfds = 0; /* number of kernel file descriptors */
    size_t* tindices = NULL; /* target indices */
    size_t* kindices = NULL; /* kernel indices */
    long tevents = 0; /* the number of target events */
    long kevents = 0; /* the number of kernel events */

    /* special case: if nfds is zero */
    if (nfds == 0)
    {
        long r;
        long params[6] = {(long)NULL, nfds, timeout};
        ECHECK((r = libos_tcall(SYS_poll, params)));
        ret = r;
        goto done;
    }

    if (!fds && nfds)
        ERAISE(-EFAULT);

    if (!(fdtable = libos_fdtable_current()))
        ERAISE(-ENOSYS);

    if (!(tfds = calloc(nfds, sizeof(struct pollfd))))
        ERAISE(-ENOMEM);

    if (!(kfds = calloc(nfds, sizeof(struct pollfd))))
        ERAISE(-ENOMEM);

    if (!(tindices = calloc(nfds, sizeof(size_t))))
        ERAISE(-ENOMEM);

    if (!(kindices = calloc(nfds, sizeof(size_t))))
        ERAISE(-ENOMEM);

    /* Split fds[] into two arrays: tfds[] (target) and kfds[] (kernel) */
    for (nfds_t i = 0; i < nfds; i++)
    {
        int tfd;
        libos_fdtable_type_t type;
        libos_fdops_t* fdops;
        void* object;

        /* get the device for this file descriptor */
        ECHECK(libos_fdtable_get_any(
            fdtable, fds[i].fd, &type, (void**)&fdops, (void**)&object));

        /* get the target fd for this object (or -ENOTSUP) */
        if ((tfd = (*fdops->fd_target_fd)(fdops, object)) >= 0)
        {
            tfds[tnfds].events = fds[i].events;
            tfds[tnfds].fd = tfd;
            tindices[tnfds] = i;
            tnfds++;
        }
        else if (tfd == -ENOTSUP)
        {
            kfds[knfds].events = fds[i].events;
            kfds[knfds].fd = fds[i].fd;
            kindices[knfds] = i;
            knfds++;
        }
        else
        {
            ERAISE(-EINVAL);
        }
    }

    /* pre-poll for kernel events */
    {
        ECHECK((kevents = _poll_kernel(kfds, knfds)));

        /* if any kernel events were found, change timeout to zero */
        if (kevents)
            timeout = 0;
    }

    /* poll for target events */
    if (tnfds && tfds)
    {
        ECHECK((tevents = libos_tcall_poll(tfds, tnfds, timeout)));
    }
    else
    {
        ECHECK((tevents = libos_tcall_poll(NULL, tnfds, timeout)));
    }

    /* post-poll for kernel events (avoid if already polled above) */
    if (kevents == 0)
    {
        ECHECK((kevents = _poll_kernel(kfds, knfds)));
    }

    /* update fds[] with the target events */
    for (nfds_t i = 0; i < tnfds; i++)
        fds[tindices[i]].revents = tfds[i].revents;

    /* update fds[] with the kernel events */
    for (nfds_t i = 0; i < knfds; i++)
        fds[kindices[i]].revents = kfds[i].revents;

    ret = tevents + kevents;

done:

    if (tfds)
        free(tfds);

    if (kfds)
        free(kfds);

    if (tindices)
        free(tindices);

    if (kindices)
        free(kindices);

    return ret;
}
