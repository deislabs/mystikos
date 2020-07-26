#ifndef _OEL_SYSCALLUTILS_H
#define _OEL_SYSCALLUTILS_H

#include <sys/syscall.h>

const char* syscall_str(long n);

#define OEL_SYS_trace 1000
#define OEL_SYS_trace_ptr 1001
#define OEL_SYS_dump_stack 1002
#define OEL_SYS_dump_ehdr 1003

#endif /* _OEL_SYSCALLUTILS_H */
