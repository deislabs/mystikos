#ifndef _LIBOS_SYSCALL_H
#define _LIBOS_SYSCALL_H

#include <sys/syscall.h>
#include <fcntl.h>
#include <stdbool.h>

#define LIBOS_SYS_trace 1000
#define LIBOS_SYS_trace_ptr 1001
#define LIBOS_SYS_dump_stack 1002
#define LIBOS_SYS_dump_ehdr 1003

#define SYS_libos_open 1008

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
