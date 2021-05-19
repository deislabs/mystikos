// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_HOST_EXEC_H
#define _MYST_HOST_EXEC_H

#include <myst/options.h>

int exec_action(int argc, const char* argv[], const char* envp[]);

int exec_launch_enclave(
    const char* enc_path,
    oe_enclave_type_t type,
    uint32_t flags,
    const char* argv[],
    const char* envp[],
    struct myst_options* options,
    size_t max_threads);

#endif /* _MYST_HOST_EXEC_H */
