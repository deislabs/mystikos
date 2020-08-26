// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _LIBOS_SYSCALLEXT_H
#define _LIBOS_SYSCALLEXT_H

#include <libos/types.h>

/* libos-specific syscalls */

enum
{
    SYS_libos_trace = 1001,
    SYS_libos_trace_ptr = 1002,
    SYS_libos_dump_stack = 1003,
    SYS_libos_dump_ehdr = 1004,
    SYS_libos_dump_argv = 1005,
    SYS_libos_add_symbol_file = 1006,
    SYS_libos_load_symbols = 1007,
    SYS_libos_unload_symbols = 1008,
    SYS_libos_gen_creds = 1009,
    SYS_libos_free_creds = 1010,
};

#endif /* _LIBOS_SYSCALLEXT_H */
