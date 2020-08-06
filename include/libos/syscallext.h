// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _LIBOS_SYSCALLEXT_H
#define _LIBOS_SYSCALLEXT_H

#include <libos/types.h>

/* libos-specific syscalls */

#define SYS_libos_trace 1001
#define SYS_libos_trace_ptr 1002
#define SYS_libos_dump_stack 1003
#define SYS_libos_dump_ehdr 1004
#define SYS_libos_dump_argv 1005

#endif /* _LIBOS_SYSCALLEXT_H */
