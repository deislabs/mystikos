#ifndef _LIBOS_SYSCALL_H
#define _LIBOS_SYSCALL_H

#include <sys/syscall.h>
#include <fcntl.h>
#include <stdbool.h>

enum
{
    LIBOS_SYS_base = 1024,
    LIBOS_SYS_trace,
    LIBOS_SYS_trace_ptr,
    LIBOS_SYS_dump_stack,
    LIBOS_SYS_dump_ehdr,
    LIBOS_SYS_open,
    LIBOS_SYS_read,
    LIBOS_SYS_write,
    LIBOS_SYS_close,
};

void libos_trace_syscalls(bool flag);

long libos_syscall(long n, long params[6]);

const char* syscall_str(long n);

int libos_get_exit_status(void);

int libos_set_exit_jump(void);

void libos_set_rootfs(const char* path);

long libos_syscall_ret(long r);

long libos_syscall(long n, long params[6]);

long libos_syscall_open(const char* pathname, int flags, mode_t mode);

long libos_syscall_close(int fd);

long libos_syscall_read(int fd, void* buf, size_t count);

long libos_syscall_write(int fd, const void* buf, size_t count);

#endif /* _LIBOS_SYSCALL_H */
