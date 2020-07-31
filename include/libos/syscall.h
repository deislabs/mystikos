#ifndef _LIBOS_SYSCALL_H
#define _LIBOS_SYSCALL_H

#include <sys/syscall.h>
#include <stdbool.h>

#define LIBOS_SYS_trace 1000
#define LIBOS_SYS_trace_ptr 1001
#define LIBOS_SYS_dump_stack 1002
#define LIBOS_SYS_dump_ehdr 1003

void libos_trace_syscalls(bool flag);

long libos_syscall(long n, long params[6]);

const char* syscall_str(long n);

int libos_get_exit_status(void);

int libos_set_exit_jump(void);

void libos_set_rootfs(const char* path);

#endif /* _LIBOS_SYSCALL_H */
