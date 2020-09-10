// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <libos/json.h>
#include <stdio.h>

typedef struct _config_parsed_data_t
{
    // OE config specific settings. Just output to file
    FILE* oe_config_out_file;

    // LibOS config values
    int64_t user_pages;
    char* application_path;
    unsigned char allow_host_parameters;
    char** application_parameters;
    size_t application_parameters_count;

    // Internal data
    void* buffer;
} config_parsed_data_t;

int parse_config(
    const char* config_data,
    size_t config_size,
    config_parsed_data_t* parsed_data);
int free_config(config_parsed_data_t* parsed_data);
