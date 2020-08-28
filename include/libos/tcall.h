// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_TCALL_H
#define _LIBOS_TCALL_H

#include <libos/defs.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

typedef enum libos_tcall_number
{
    LIBOS_TCALL_RANDOM = 2048,
    LIBOS_TCALL_THREAD_SELF,
    LIBOS_TCALL_ALLOCATE,
    LIBOS_TCALL_DEALLOCATE,
    LIBOS_TCALL_VSNPRINTF,
    LIBOS_TCALL_WRITE_CONSOLE,
    LIBOS_TCALL_GEN_CREDS,
    LIBOS_TCALL_FREE_CREDS,
    LIBOS_TCALL_CLOCK_GETTIME,
    LIBOS_TCALL_ISATTY,
    LIBOS_TCALL_ADD_SYMBOL_FILE,
    LIBOS_TCALL_LOAD_SYMBOLS,
    LIBOS_TCALL_UNLOAD_SYMBOLS,
    LIBOS_TCALL_CREATE_HOST_THREAD,
}
libos_tcall_number_t;

long libos_tcall(long n, long params[6]);

typedef long (*libos_tcall_t)(long n, long params[6]);

long libos_tcall_random(void* data, size_t size);

long libos_tcall_thread_self(void);

long libos_tcall_vsnprintf(
    char* str,
    size_t size,
    const char* format,
    va_list ap);

long libos_tcall_write_console(
    int fd,
    const void* buf,
    size_t count);

long libos_tcall_create_host_thread(uint64_t cookie);

#endif /* _LIBOS_TCALL_H */
