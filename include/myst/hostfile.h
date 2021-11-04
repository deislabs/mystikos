// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_HOSTFILE_H
#define _MYST_HOSTFILE_H

#include <stddef.h>

#include <myst/defs.h>

// Load a file from the host file system (zero-terminates data but does
// not include the terminator in the size)
int myst_load_host_file(const char* path, void** data, size_t* size);

// Copy a file from the host file system to enclave
int myst_copy_host_file_to_enc(const char* host_path, const char* enc_path);
int myst_copy_host_files(
    const char** copy_host_files_data,
    size_t copy_host_files_size);

#endif /* _MYST_HOSTFILE_H */
