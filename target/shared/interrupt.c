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

// #define TRACE

#ifdef TRACE
#define T(EXPR) EXPR
#else
#define T(EXPR)
#endif

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

    for (;;)
    {
        bool is_inprogress = false;

        /* attempt the syscall */
        {
            long syscall_ret = 0;
            errno = 0;

            /* Call actual libc function in case it does extra processing */
            switch (n)
            {
                case SYS_connect:
                {
                    syscall_ret = connect((int)a, (void*)b, (socklen_t)c);
                    break;
                }
                case SYS_accept4:
                {
                    syscall_ret = accept4((int)a, (void*)b, (void*)c, (int)d);
                    break;
                }
                case SYS_read:
                {
                    syscall_ret = read((int)a, (void*)b, (size_t)c);
                    break;
                }
                case SYS_write:
                {
                    syscall_ret = write((int)a, (void*)b, (size_t)c);
                    break;
                }
                case SYS_sendmsg:
                {
                    syscall_ret = sendmsg((int)a, (void*)b, (int)c);
                    break;
                }
                case SYS_recvmsg:
                {
                    syscall_ret = recvmsg((int)a, (void*)b, (int)c);
                    break;
                }
                case SYS_sendto:
                {
                    syscall_ret = sendto(
                        (int)a,
                        (void*)b,
                        (size_t)c,
                        (int)d,
                        (void*)e,
                        (socklen_t)f);
                    break;
                }
                case SYS_recvfrom:
                {
                    syscall_ret = recvfrom(
                        (int)a,
                        (void*)b,
                        (size_t)c,
                        (int)d,
                        (void*)e,
                        (socklen_t*)f);
                    break;
                }
                default:
                {
                    ERAISE(-ENOTSUP);
                }
            }

            T(printf(
                  "blocking syscall %ld returned (retry=%d) %ld\n",
                  n,
                  (int)retry,
                  syscall_ret < 0 ? (long)-errno : syscall_ret);)

            if (syscall_ret >= 0)
            {
                ret = syscall_ret;
                T(printf(".. syscall returned >= 0, we are done\n");)
                goto done;
            }

            // if (!(retry && (errno == EAGAIN || errno == EINPROGRESS)))
            if (!retry || (errno != EAGAIN && errno != EINPROGRESS))
            {
                T(printf(
                      "... retry=%d and errno = %d so we are done\n",
                      (int)retry,
                      errno);)
                ERAISE(-errno);
            }
            if (errno == EINPROGRESS)
                is_inprogress = true;

            T(printf(
                  "continuing after syscall error, retry=%d, errno=%d....\n",
                  (int)retry,
                  errno);)
        }

        /* block until interruption or fd is ready */
        for (;;)
        {
            /* wait indefinitely for event or EINTR */
            int poll_ret;
            struct pollfd fds[1];
            fds[0].fd = fd;
            fds[0].events = events;
            fds[0].revents = 0;

            /* atomically unblock signals during ppoll() */
            sigset_t sigmask;
            sigemptyset(&sigmask);
            poll_ret = ppoll(fds, 1, NULL, &sigmask);

            T(printf(
                  "blocking syscall poll returned %d\n",
                  poll_ret < 0 ? -errno : poll_ret);)

            /* return error, probably -EINTR */
            if (poll_ret < 0)
            {
                T(printf("returning because poll had error...\n");)
                ERAISE(-errno);
            }

            /* if event occurred, then perform operation */
            if (poll_ret == 1 && (fds[0].revents & events))
            {
                if (is_inprogress)
                {
                    T(printf("poll told us we have something and the syscall "
                             "error was EINPROGRESS so we are done\n");)
                    ret = -EINPROGRESS;
                    goto done;
                }
                else
                {
                    T(printf(
                          "poll told us we have something so trying syscall "
                          "again (fds[0].revents=%d & events=%d)...\n",
                          fds[0].revents,
                          events);)
                    break;
                }
            }
        }
    }

done:

    return ret;
}

int myst_tcall_connect_block(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    int ret = 0;
    int r;

    /* check whether socket is already connected (for SOCK_STREAM only) */
    {
        int type = 0;
        socklen_t optlen = sizeof(type);

        if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &optlen) == 0 &&
            type == SOCK_STREAM)
        {
            struct pollfd fds[1];
            fds[0].fd = sockfd;
            fds[0].events = POLLOUT;
            fds[0].revents = 0;

            if (poll(fds, 1, 0) == 1 && !(fds[0].revents & POLLHUP))
                ERAISE(-EISCONN);
        }
    }

    /* perform the interruptible syscall */
    r = myst_interruptible_syscall(
        SYS_connect, sockfd, POLLOUT, true, sockfd, addr, addrlen);

    /* If EINPROGRESS, then get the error result from the socket */
    if (r == -EINPROGRESS)
    {
        int err;
        socklen_t optlen = sizeof(err);
        errno = 0;

        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &optlen) < 0)
            return -errno;

        ECHECK(-err);
    }
    else
    {
        ECHECK(r);
    }

done:
    return ret;
}
