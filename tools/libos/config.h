// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <libos/json.h>
#include <stdio.h>
#include <sys/types.h>

typedef struct _config_parsed_data_t
{
    // File handle for writing OE based configuration for oesign
    FILE* oe_config_out_file;

    // OE settings
    unsigned char oe_debug;
    uint64_t oe_num_heap_pages; // NumKernelPages
    uint64_t oe_num_stack_pages;
    uint64_t oe_num_user_threads;
    unsigned short oe_product_id;
    unsigned short oe_security_version;

    // LibOS config values
    int64_t user_pages;
    char* application_path;
    unsigned char allow_host_parameters;
    char** application_parameters;
    size_t application_parameters_count;
    char** enclave_environment_variables;
    size_t enclave_environment_variables_count;
    char** host_environment_variables;
    size_t host_environment_variables_count;

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

int free_config(config_parsed_data_t* parsed_data);
