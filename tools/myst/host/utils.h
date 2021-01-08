// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _HOST_MYST_UTILS_H
#define _HOST_MYST_UTILS_H

#include <limits.h>

// print error and exit process with 1
void _err(const char* fmt, ...);

// sets the program file name of the process
const char* set_program_file(const char* program);

// gets the previously set program file
const char* get_program_file();

const int format_mystenc(char* path, size_t size);

const int format_libmystcrt(char* path, size_t size);

const int format_libmystkernel(char* path, size_t size);

// delete a directory and anything in it
// NOTE: this is not thread safe!
int remove_recursive(const char* path);

int cli_getopt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg);

#endif /* _HOST_MYST_UTILS_H */
