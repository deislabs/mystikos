// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _TOOLS_MYST_CONFIG_H
#define _TOOLS_MYST_CONFIG_H

#include <myst/json.h>
#include <myst/kernel.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef MYST_ENABLE_GCOV
#define ENCLAVE_STACK_SIZE (8 * 8192)
#else
#define ENCLAVE_STACK_SIZE 8192
#endif

#define ENCLAVE_HEAP_SIZE (256 * 1024)

#define ENCLAVE_MAX_THREADS MYST_MAX_KSTACKS

#define ENCLAVE_PRODUCT_ID 1

#define ENCLAVE_SECURITY_VERSION 1

#define ENCLAVE_EXTENDED_PRODUCT_ID ({0})

#define ENCLAVE_FAMILY_ID ({0})

#define ENCLAVE_DEBUG true

#define ENCLAVE_CAPTURE_PF_GP_EXCEPTIONS true

#define ENCLAVE_REQUIRE_KSS false

#ifdef MYST_ENABLE_ZERO_BASE_ENCLAVES
#define ENCLAVE_CREATE_ZERO_BASE_ENCLAVE true
#define ENCLAVE_START_ADDRESS 0x000100000000 /* fixed at 4gb */
#else
#define ENCLAVE_CREATE_ZERO_BASE_ENCLAVE false
#define ENCLAVE_START_ADDRESS 0
#endif

typedef struct _config_parsed_data_t
{
    // The version at the start of the configuration tells the parser which
    // version of configuration schema we need to use for backwards
    // compatibility.
    char* configuration_version;

    // OE settings
    unsigned char oe_debug;
    uint64_t oe_num_stack_pages;
    uint64_t oe_num_user_threads;
    unsigned short oe_product_id;
    unsigned short oe_security_version;
    bool oe_create_zero_base;
    uint64_t oe_start_address;

    // Mystikos config values
    uint64_t heap_pages; // heap_pages*4096=value-in-config
    char* application_path;
    unsigned char allow_host_parameters;
    char** application_parameters;
    size_t application_parameters_count;
    char** enclave_environment_variables;
    size_t enclave_environment_variables_count;
    char** host_environment_variables;
    size_t host_environment_variables_count;
    char* cwd;
    char* hostname;
    myst_fork_mode_t fork_mode;
    myst_mounts_config_t mounts;
    myst_wanted_secrets_t wanted_secrets;
    bool no_brk;
    bool exec_stack;
    bool unhandled_syscall_enosys;
    bool host_uds;
    int syslog_level;

    size_t main_stack_size;
    size_t thread_stack_size;
    /* maximum number of CPUs in the kernel (for thread affinity) */
    size_t max_affinity_cpus;

    // Internal data
    void* buffer;
    size_t buffer_length;
} config_parsed_data_t;

int parse_config_from_buffer(
    const char* config_data,
    size_t config_size,
    config_parsed_data_t* parsed_data);

int parse_config_from_file(
    const char* config_path,
    config_parsed_data_t* parsed_data);

int write_oe_config_fd(int fd, config_parsed_data_t* parsed_data);

int free_config(config_parsed_data_t* parsed_data);

int parse_config(config_parsed_data_t* parsed_data);

#endif /* _TOOLS_MYST_CONFIG_H */
