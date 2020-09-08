// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _HOST_LIBOS_UTILS_H
#define _HOST_LIBOS_UTILS_H

#include <limits.h>

// print error and exit process with 1
void _err(const char* fmt, ...);

// sets the program file name of the process
const char *set_program_file(const char *program);

// gets the previously set program file
const char *get_program_file();

int format_libosenc(char* path, size_t size);

int format_liboscrt(char* path, size_t size);

int format_liboskernel(char* path, size_t size);

#endif /* _HOST_LIBOS_UTILS_H */
