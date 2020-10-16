#ifndef _LIBOS_PROCESS_H
#define _LIBOS_PROCESS_H

#include <libos/thread.h>
#include <sys/types.h>
#include <unistd.h>

LIBOS_INLINE pid_t libos_getsid(void)
{
    return libos_thread_self()->sid;
}

LIBOS_INLINE pid_t libos_getppid(void)
{
    return libos_thread_self()->ppid;
}

LIBOS_INLINE pid_t libos_getpid(void)
{
    return libos_thread_self()->pid;
}

#endif /* _LIBOS_PROCESS_H */
