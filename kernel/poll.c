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

long libos_syscall_poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    long ret = 0;
    struct pollfd* tfds = NULL; /* target file descriptors */
    libos_fdtable_t* fdtable;
    long retval;

    if (!fds || nfds == 0)
        ERAISE(-EINVAL);

    if (!(tfds = calloc(nfds, sizeof(struct pollfd))))
        ERAISE(-ENOMEM);

    if (!(fdtable = libos_fdtable_current()))
        ERAISE(-ENOSYS);

    /* convert kernel fds to target fds */
    for (nfds_t i = 0; i < nfds; i++)
    {
        int tfd;
        libos_fdtable_type_t type;
        libos_fdops_t* fdops;
        void* object;

        /* get the device for this file descriptor */
        ECHECK(libos_fdtable_get_any(
            fdtable, fds[i].fd, &type, (void**)&fdops, (void**)&object));

        /* get the target fd for this object */
        ECHECK((tfd = (*fdops->fd_target_fd)(fdops, object)));

        tfds[i].events = fds[i].events;
        tfds[i].fd = tfd;
    }

    /* perform syscall */
    {
        long params[6] = {(long)tfds, nfds, timeout};
        ECHECK((retval = libos_tcall(SYS_poll, params)));
    }

    /* Update kernel events with recieved target events */
    for (nfds_t i = 0; i < nfds; i++)
        fds[i].revents = tfds[i].revents;

    ret = retval;

done:

    if (tfds)
        free(tfds);

    return ret;
}
