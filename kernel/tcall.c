#include <errno.h>
#include <libos/tcall.h>

long libos_tcall_random(void* data, size_t size)
{
    long params[6] = {(long)data, (long)size};
    return libos_tcall(LIBOS_TCALL_RANDOM, params);
}

long libos_tcall_thread_self(void)
{
    long params[6] = {0};
    return libos_tcall(LIBOS_TCALL_THREAD_SELF, params);
}

long libos_tcall_vsnprintf(
    char* str,
    size_t size,
    const char* format,
    va_list ap)
{
    long params[6] = {0};
    params[0] = (long)str;
    params[1] = (long)size;
    params[2] = (long)format;
    params[3] = (long)ap;
    return libos_tcall(LIBOS_TCALL_VSNPRINTF, params);
}

long libos_tcall_write_console(int fd, const void* buf, size_t count)
{
    long params[6] = {0};
    params[0] = (long)fd;
    params[1] = (long)buf;
    params[2] = (long)count;
    return libos_tcall(LIBOS_TCALL_WRITE_CONSOLE, params);
}

long libos_tcall_create_host_thread(uint64_t cookie)
{
    long params[6] = {0};
    params[0] = (long)cookie;
    return libos_tcall(LIBOS_TCALL_CREATE_HOST_THREAD, params);
}

long libos_tcall_wait(uint64_t event, const struct timespec* timeout)
{
    long params[6] = {0};
    params[0] = (long)event;
    params[1] = (long)timeout;
    return libos_tcall(LIBOS_TCALL_WAIT, params);
}

long libos_tcall_wake(uint64_t event)
{
    long params[6] = {0};
    params[0] = (long)event;
    return libos_tcall(LIBOS_TCALL_WAKE, params);
}

long libos_tcall_export_file(const char* path, const void* data, size_t size)
{
    long params[6] = {(long)path, (long)data, (long)size};
    return libos_tcall(LIBOS_TCALL_EXPORT_FILE, params);
}

long libos_tcall_wake_wait(
    uint64_t waiter_event,
    uint64_t self_event,
    const struct timespec* timeout)
{
    long params[6] = {0};
    params[0] = (long)waiter_event;
    params[1] = (long)self_event;
    params[2] = (long)timeout;
    return libos_tcall(LIBOS_TCALL_WAKE_WAIT, params);
}
