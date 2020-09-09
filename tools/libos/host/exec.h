// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

int _exec(int argc, const char* argv[]);
int exec_launch_enclave(
    const char *enc_path, 
    oe_enclave_type_t type, 
    uint32_t flags,
    const char *argv[],
    struct libos_options *options);
int exec_get_opt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg);
