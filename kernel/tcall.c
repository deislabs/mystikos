#include <errno.h>
#include <libos/tcall.h>

long libos_tcall_random(void* data, size_t size)
{
    long params[6] = { (long)data, (long)size };
    return libos_tcall(LIBOS_TCALL_RANDOM, params);
}

long libos_tcall_thread_self(void)
{
    long params[6] = { 0 };
    return libos_tcall(LIBOS_TCALL_THREAD_SELF, params);
}

long libos_tcall_vsnprintf(
    char* str,
    size_t size,
    const char* format,
    va_list ap)
{
    long params[6] = { 0 };
    params[0] = (long)str;
    params[1] = (long)size;
    params[2] = (long)format;
    params[3] = (long)ap;
    return libos_tcall(LIBOS_TCALL_VSNPRINTF, params);
}

long libos_tcall_write_console(
    int fd,
    const void* buf,
    size_t count)
{
    long params[6] = { 0 };
    params[0] = (long)fd;
    params[1] = (long)buf;
    params[2] = (long)count;
    return libos_tcall(LIBOS_TCALL_WRITE_CONSOLE, params);
}

long libos_tcall_create_host_thread(uint64_t cookie)
{
    long params[6] = { 0 };
    params[0] = (long)cookie;
    return libos_tcall(LIBOS_TCALL_CREATE_HOST_THREAD, params);
}

long libos_tcall_wait(pid_t tid, const struct timespec* timeout)
{
    (void)tid;
    (void)timeout;
    return -ENOTSUP;
}

long libos_tcall_wake(pid_t tid)
{
    (void)tid;
    return -ENOTSUP;
}

long libos_tcall_wake_wait(
    pid_t waiter_tid,
    pid_t self_tid,
    const struct timespec* timeout)
{
    (void)waiter_tid;
    (void)self_tid;
    (void)timeout;
    return -ENOTSUP;
}
