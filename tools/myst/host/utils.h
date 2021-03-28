// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _HOST_MYST_UTILS_H
#define _HOST_MYST_UTILS_H

#include <myst/defs.h>
#include <sys/user.h>

#include <myst/kernel.h>

// default Mystikos RAM size
#define DEFAULT_MMAN_SIZE (64 * 1024 * 1024)

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

long myst_add_symbol_file_by_path(
    const char* path,
    const void* text_data,
    size_t text_size);

int init_kernel_args(
    myst_kernel_args_t* args,
    int argc,
    const char* argv[],
    int envc,
    const char* envp[],
    const void* regions_end,
    const void* image_data,
    size_t image_size,
    size_t max_threads,
    bool trace_errors,
    bool trace_syscalls,
    bool export_ramfs,
    bool have_syscall_instruction,
    bool tee_debug_mode,
    uint64_t thread_event,
    long (*tcall)(long n, long params[6]),
    const char* rootfs,
    char* err,
    size_t err_size);

#endif /* _HOST_MYST_UTILS_H */
