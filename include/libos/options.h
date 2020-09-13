#ifndef _LIBOS_OPTIONS_H
#define _LIBOS_OPTIONS_H

#include <libos/types.h>

typedef struct libos_options
{
    bool trace_syscalls;
    bool have_syscall_instruction;
    bool export_ramfs;
} libos_options_t;

extern libos_options_t __options;

#endif /* _LIBOS_OPTIONS_H */
