#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/syscall.h>

#include <myst/config.h>
#include <myst/tcall.h>

long myst_tcall_epoll_wait(
    int epfd,
    struct epoll_event* events,
    size_t maxevents,
    int timeout)
{
#if (MYST_INTERRUPT_EPOLL_WITH_SIGNAL == 1)
    sigset_t sigmask;

    /* Temporarily unblock signals */
    sigemptyset(&sigmask);

    long ret = epoll_pwait(epfd, events, maxevents, timeout, &sigmask);

    if (ret < 0)
        ret = -errno;

#ifdef MYST_TRACE_THREAD_INTERRUPTIONS
    if (ret == -EINTR)
    {
        pid_t tid = (pid_t)syscall(SYS_gettid);
        printf(">>>>>>>> epoll_wait() interrupted: tid=%d\n", tid);
        fflush(stdout);
    }
#endif

    return ret;
#elif (MYST_INTERRUPT_EPOLL_WITH_SIGNAL == -1)
    long ret = epoll_wait(epfd, events, maxevents, timeout);

    if (ret < 0)
        return -errno;

    return ret;
#else
#error "MYST_INTERRUPT_EPOLL_WITH_SIGNAL undefined"
#endif
}
