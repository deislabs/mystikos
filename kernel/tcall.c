#include <errno.h>
#include <libos/fsgs.h>
#include <libos/strings.h>
#include <libos/tcall.h>
#include <libos/thread.h>

long libos_tcall_random(void* data, size_t size)
{
    long params[6] = {(long)data, (long)size};
    return libos_tcall(LIBOS_TCALL_RANDOM, params);
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

long libos_tcall_read_console(int fd, void* buf, size_t count)
{
    long params[6] = {0};
    params[0] = (long)fd;
    params[1] = (long)buf;
    params[2] = (long)count;
    return libos_tcall(LIBOS_TCALL_READ_CONSOLE, params);
}

long libos_tcall_write_console(int fd, const void* buf, size_t count)
{
    long params[6] = {0};
    params[0] = (long)fd;
    params[1] = (long)buf;
    params[2] = (long)count;
    return libos_tcall(LIBOS_TCALL_WRITE_CONSOLE, params);
}

long libos_tcall_create_thread(uint64_t cookie)
{
    long params[6] = {0};
    params[0] = (long)cookie;
    return libos_tcall(LIBOS_TCALL_CREATE_THREAD, params);
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

long libos_tcall_set_run_thread_function(libos_run_thread_t function)
{
    long params[6] = {(long)function};
    return libos_tcall(LIBOS_TCALL_SET_RUN_THREAD_FUNCTION, params);
}

long libos_tcall_target_stat(libos_target_stat_t* target_stat)
{
    long params[6] = {(long)target_stat};
    return libos_tcall(LIBOS_TCALL_TARGET_STAT, params);
}

long libos_tcall_set_tsd(uint64_t value)
{
    long params[6] = {(long)value};
    return libos_tcall(LIBOS_TCALL_SET_TSD, params);
}

long libos_tcall_get_tsd(uint64_t* value)
{
    long params[6] = {(long)value};
    return libos_tcall(LIBOS_TCALL_GET_TSD, params);
}

long libos_tcall_get_errno_location(int** ptr)
{
    long params[6] = {(long)ptr};
    return libos_tcall(LIBOS_TCALL_GET_ERRNO_LOCATION, params);
}
