// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _HOST_MYST_UTILS_H
#define _HOST_MYST_UTILS_H

#include <myst/args.h>
#include <myst/defs.h>
#include <myst/kernel.h>
#include <myst/options.h>
#include <myst/sha256.h>
#include <sys/user.h>

// default Mystikos RAM size
#define DEFAULT_MMAN_SIZE (64 * 1024 * 1024)

// print error with program name prepended and exit process with 1
MYST_PRINTF_FORMAT(1, 2)
void _err(const char* fmt, ...);

// only print error with program name prepended
MYST_PRINTF_FORMAT(1, 2)
void _err_noexit(const char* fmt, ...);

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

int cli_get_mapping_opts(
    int* argc,
    const char* argv[],
    myst_host_enc_uid_gid_mappings* uid_gid_mappings);

int cli_get_mount_mapping_opts(
    int* argc,
    const char* argv[],
    myst_args_t* mappings);

int get_fork_mode_opts(
    int* argc,
    const char* argv[],
    myst_fork_mode_t* fork_mode);

int get_syslog_level_opts(int* argc, const char* argv[], int* syslog_level);

long myst_add_symbol_file_by_path(
    const char* path,
    const void* text_data,
    size_t text_size);

extern void* __image_data;
extern size_t __image_size;

#endif /* _HOST_MYST_UTILS_H */
