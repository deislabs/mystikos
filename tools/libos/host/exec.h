// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _LIBOS_HOST_EXEC_H
#define _LIBOS_HOST_EXEC_H

struct libos_options;

int exec_action(int argc, const char* argv[]);

int exec_launch_enclave(
    const char* enc_path,
    oe_enclave_type_t type,
    uint32_t flags,
    const char* argv[],
    struct libos_options* options);

#endif /* _LIBOS_HOST_EXEC_H */
