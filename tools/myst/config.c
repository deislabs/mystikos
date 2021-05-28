// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <memory.h>
#include <myst/file.h>
#include <myst/kernel.h>
#include <myst/round.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "shared.h"

#define CONFIG_RAISE(CONFIG_ERR)                            \
    do                                                      \
    {                                                       \
        ret = CONFIG_ERR;                                   \
        if (ret != 0)                                       \
        {                                                   \
            fprintf(                                        \
                stderr,                                     \
                "CONFIG_RAISE: %s(%u): %s: errno=%d: %s\n", \
                __FILE__,                                   \
                __LINE__,                                   \
                __FUNCTION__,                               \
                CONFIG_ERR,                                 \
                json_result_string(CONFIG_ERR));            \
            goto done;                                      \
        }                                                   \
    } while (0)

static json_result_t _extract_mem_size(
    json_type_t type,
    const json_union_t* un,
    uint64_t* num_pages)
{
    json_result_t ret = JSON_FAILED;
    uint64_t value;

    if (num_pages == NULL)
        CONFIG_RAISE(JSON_FAILED);

    if (type == JSON_TYPE_INTEGER)
        value = (uint64_t)un->integer; // number in bytes
    else if (type == JSON_TYPE_STRING)
    {
        if (myst_expand_size_string_to_ulong(un->string, &value) != 0)
        {
            fprintf(
                stderr,
                "ERROR: Configuration: MemSize values can be in megabyte (m), "
                "kilobytes (k) or bytes\n");
            fprintf(stderr, "for example \"10m\", \"100k\" or \"100000000\"\n");
            CONFIG_RAISE(JSON_OUT_OF_BOUNDS);
        }
    }
    else
        CONFIG_RAISE(JSON_TYPE_MISMATCH);

    if (myst_round_up(value, PAGE_SIZE, &value) != 0)
        CONFIG_RAISE(JSON_FAILED);

    value /= PAGE_SIZE;

    *num_pages = value;

    ret = JSON_OK;
done:
    return ret;
}

static json_result_t _json_read_callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* _parsed_data)
{
    config_parsed_data_t* parsed_data = (config_parsed_data_t*)_parsed_data;
    json_result_t ret = JSON_FAILED;

    switch (reason)
    {
        case JSON_REASON_VALUE:
        {
            // configuration schema version. This should be the first
            // entry in the JSON configuration so we know how to parse
            // everything else
            if (json_match(parser, "version") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                {
                    parsed_data->configuration_version = un->string;
                    if (strcmp(parsed_data->configuration_version, "0.1") != 0)
                        CONFIG_RAISE(JSON_UNSUPPORTED);
                }
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }

            // OE Config generation only
            else if (json_match(parser, "Debug") == JSON_OK)
            {
                if (((type == JSON_TYPE_BOOLEAN) && un->boolean) ||
                    ((type == JSON_TYPE_INTEGER) && un->integer))
                {
                    parsed_data->oe_debug = 1;
                }
                else if (
                    (type == JSON_TYPE_BOOLEAN) || (type == JSON_TYPE_INTEGER))
                {
                    parsed_data->oe_debug = 0;
                }
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "StackMemSize") == JSON_OK)
            {
                ret = _extract_mem_size(
                    type, un, &parsed_data->oe_num_stack_pages);
                if (ret != JSON_OK)
                    CONFIG_RAISE(ret);
            }
            else if (json_match(parser, "NumUserThreads") == JSON_OK)
            {
                if (type == JSON_TYPE_INTEGER)
                {
                    parsed_data->oe_num_user_threads = (uint64_t)un->integer;
                }
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "ProductID") == JSON_OK)
            {
                if (type == JSON_TYPE_INTEGER)
                {
                    parsed_data->oe_product_id = (unsigned short)un->integer;
                }
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "SecurityVersion") == JSON_OK)
            {
                if (type == JSON_TYPE_INTEGER)
                {
                    parsed_data->oe_security_version =
                        (unsigned short)un->integer;
                }
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }

            // Mystikos configuration
            else if (json_match(parser, "UserMemSize") == JSON_OK)
            {
                /* legacy setting (kept for backwards compatibility) */
                ret = _extract_mem_size(type, un, &parsed_data->heap_pages);
                if (ret != JSON_OK)
                    CONFIG_RAISE(ret);
            }
            else if (json_match(parser, "MemorySize") == JSON_OK)
            {
                ret = _extract_mem_size(type, un, &parsed_data->heap_pages);
                if (ret != JSON_OK)
                    CONFIG_RAISE(ret);
            }
            else if (json_match(parser, "MaxAffinityCPUs") == JSON_OK)
            {
                if (type != JSON_TYPE_INTEGER)
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);

                if (un->integer <= 0)
                    CONFIG_RAISE(JSON_OUT_OF_BOUNDS);

                parsed_data->max_affinity_cpus = (size_t)un->integer;
            }
            else if (json_match(parser, "ApplicationPath") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->application_path = un->string;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "HostApplicationParameters") == JSON_OK)
            {
                if (type == JSON_TYPE_BOOLEAN)
                    parsed_data->allow_host_parameters = un->boolean;
                else if (type == JSON_TYPE_INTEGER)
                    parsed_data->allow_host_parameters =
                        (un->integer == 0) ? 0 : 1;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "ApplicationParameters") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->application_parameters[parser->path[0].index] =
                        un->string;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "EnvironmentVariables") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data
                        ->enclave_environment_variables[parser->path[0].index] =
                        un->string;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "HostEnvironmentVariables") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data
                        ->host_environment_variables[parser->path[0].index] =
                        un->string;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "CurrentWorkingDirectory") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->cwd = un->string;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "Hostname") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->hostname = un->string;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "Mount.Target") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->mounts.mounts[parser->path[0].index].target =
                        un->string;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "Mount.Type") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->mounts.mounts[parser->path[0].index].fs_type =
                        un->string;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "Mount.Flags") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->mounts.mounts[parser->path[0].index]
                        .flags[parser->path[1].index] = un->string;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "Mount.PublicKey") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->mounts.mounts[parser->path[0].index]
                        .public_key = un->string;
                else if (type == JSON_TYPE_NULL)
                    parsed_data->mounts.mounts[parser->path[0].index]
                        .public_key = NULL;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "Mount.RootHash") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->mounts.mounts[parser->path[0].index].roothash =
                        un->string;
                else if (type == JSON_TYPE_NULL)
                    parsed_data->mounts.mounts[parser->path[0].index].roothash =
                        NULL;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else
            {
                // Ignore everything we dont understand
            }

            break;
        }

        case JSON_REASON_BEGIN_ARRAY:
        {
            if (json_match(parser, "ApplicationParameters") == JSON_OK)
            {
                parsed_data->application_parameters =
                    calloc(parser->path[0].size + 1, sizeof(char*));
                parsed_data->application_parameters_count =
                    parser->path[0].size;
            }
            else if (json_match(parser, "EnvironmentVariables") == JSON_OK)
            {
                parsed_data->enclave_environment_variables =
                    calloc(parser->path[0].size + 1, sizeof(char*));
                parsed_data->enclave_environment_variables_count =
                    parser->path[0].size;
            }
            else if (json_match(parser, "HostEnvironmentVariables") == JSON_OK)
            {
                parsed_data->host_environment_variables =
                    calloc(parser->path[0].size + 1, sizeof(char*));
                parsed_data->host_environment_variables_count =
                    parser->path[0].size;
            }
            else if (json_match(parser, "Mount") == JSON_OK)
            {
                parsed_data->mounts.mounts = calloc(
                    parser->path[0].size, sizeof(myst_mount_point_config_t));
                parsed_data->mounts.mounts_count = parser->path[0].size;
            }
            else if (json_match(parser, "Mount.Flags") == JSON_OK)
            {
                parsed_data->mounts.mounts[parser->path[0].index].flags =
                    calloc(parser->path[1].size, sizeof(char*));
                parsed_data->mounts.mounts[parser->path[0].index].flags_count =
                    parser->path[1].size;
            }

            break;
        }
        default:
        {
            break;
        }
    }
    ret = JSON_OK;

done:
    return ret;
}

int parse_config(config_parsed_data_t* parsed_data)
{
    int ret = -1;
    json_parser_t parser;
    const json_parser_options_t options = {1};
    static json_allocator_t allocator = {
        malloc,
        free,
    };

    /* set default settings (where settings are missing from config file) */
    {
        parsed_data->oe_num_user_threads = ENCLAVE_MAX_THREADS;
        parsed_data->oe_num_stack_pages = ENCLAVE_STACK_SIZE / PAGE_SIZE;
    }

    if ((ret = json_parser_init(
             &parser,
             (char*)parsed_data->buffer,
             parsed_data->buffer_length,
             _json_read_callback,
             parsed_data,
             &allocator,
             &options)) != JSON_OK)
    {
        CONFIG_RAISE(ret);
    }
    if ((ret = json_parser_parse(&parser)) != JSON_OK)
    {
        CONFIG_RAISE(ret);
    }

    if (parser.depth != 0)
    {
        CONFIG_RAISE(JSON_UNEXPECTED);
    }

    ret = 0;

done:
    return ret;
}

int parse_config_from_buffer(
    const char* config_data,
    size_t config_size,
    config_parsed_data_t* parsed_data)
{
    int ret = -1;

    // Duplicate the memory into the config
    parsed_data->buffer = malloc(config_size);
    if (parsed_data->buffer == NULL)
        CONFIG_RAISE(JSON_OUT_OF_MEMORY);
    memcpy(parsed_data->buffer, config_data, config_size);
    parsed_data->buffer_length = config_size;

    ret = parse_config(parsed_data);

done:
    if (ret != 0 && parsed_data->buffer)
    {
        free(parsed_data->buffer);
        parsed_data->buffer = NULL;
    }
    return ret;
}

int free_config(config_parsed_data_t* parsed_data)
{
    size_t i;
    if (parsed_data->enclave_environment_variables)
        free(parsed_data->enclave_environment_variables);
    if (parsed_data->host_environment_variables)
        free(parsed_data->host_environment_variables);
    if (parsed_data->application_parameters)
        free(parsed_data->application_parameters);
    if (parsed_data->mounts.mounts)
    {
        for (i = 0; i < parsed_data->mounts.mounts_count; i++)
        {
            if (parsed_data->mounts.mounts[i].source)
                free(parsed_data->mounts.mounts[i].source);
            if (parsed_data->mounts.mounts[i].flags)
                free(parsed_data->mounts.mounts[i].flags);
        }
        free(parsed_data->mounts.mounts);
    }
    if (parsed_data->buffer)
        free(parsed_data->buffer);
    memset(parsed_data, 0, sizeof(*parsed_data));
    return 0;
}

int write_oe_config_fd(int fd, config_parsed_data_t* parsed_data)
{
    FILE* out_file = NULL;
    int ret = -1;

    out_file = fdopen(fd, "w");
    if (out_file == NULL)
    {
        fprintf(stderr, "Failed to open OE config file for writing/n");
        goto done;
    }

    if (parsed_data->oe_debug == 0)
        fprintf(out_file, "Debug=0\n");
    else
        fprintf(out_file, "Debug=1\n");

    fprintf(out_file, "NumStackPages=%ld\n", parsed_data->oe_num_stack_pages);

    fprintf(out_file, "NumTCS=%ld\n", parsed_data->oe_num_user_threads);

    fprintf(out_file, "ProductID=%d\n", parsed_data->oe_product_id);

    fprintf(out_file, "SecurityVersion=%d\n", parsed_data->oe_security_version);

    ret = 0;

done:
    if (out_file)
        fclose(out_file);

    return ret;
}
