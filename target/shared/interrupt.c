#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <myst/eraise.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/thread.h>

long myst_tcall_interrupt_thread(pid_t tid)
{
    int ret = syscall(SYS_tkill, tid, MYST_INTERRUPT_THREAD_SIGNAL);

    if (ret < 0)
        ret = -errno;

    return ret;
}

long myst_interruptible_syscall(long n, int fd, short events, bool retry, ...)
{
    long ret = 0;
    va_list ap;
    int flags;

    if (fd < 0)
        ERAISE(-EINVAL);

    va_start(ap, retry);
    long a = va_arg(ap, long);
    long b = va_arg(ap, long);
    long c = va_arg(ap, long);
    long d = va_arg(ap, long);
    long e = va_arg(ap, long);
    long f = va_arg(ap, long);
    va_end(ap);

    /* get the file status flags */
    if ((flags = fcntl(fd, F_GETFL)) < 0)
        ERAISE(-errno);

    /* if fd is non-blocking, then perform syscall up front */
    if ((flags & O_NONBLOCK))
    {
        if ((ret = syscall(n, a, b, c, d, e, f)) < 0)
            ret = -errno;
        goto done;
    }

    /* handle blocking fd */
    for (;;)
    {
        /* atomically unblock signals during ppoll() call below */
        sigset_t sigmask;
        sigemptyset(&sigmask);

        /* wait indefinitely for event or EINTR */
        int poll_ret;
        struct pollfd fds[1];
        fds[0].fd = fd;
        fds[0].events = events;
        fds[0].revents = 0;

        poll_ret = ppoll(fds, 1, NULL, &sigmask);

        if (poll_ret < 0)
            ERAISE(-errno);

        /* if event occurred, then perform operation */
        if (poll_ret == 1 && (fds[0].revents & events))
        {
            if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
                ERAISE(-errno);

            long syscall_ret = syscall(n, a, b, c, d, e, f);

            if (fcntl(fd, F_SETFL, flags) < 0)
                ERAISE(-errno);

            if (syscall_ret >= 0)
            {
                ret = syscall_ret;
                goto done;
            }

            if (!(retry && (errno == EAGAIN || errno == EINPROGRESS)))
                ERAISE(-errno);
        }
    }

done:

    return ret;
}
