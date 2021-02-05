// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <memory.h>
#include <myst/file.h>
#include <myst/round.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"

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
        char* endptr = NULL;
        value = strtoul(un->string, &endptr, 10);
        if (endptr[0] == '\0')
        {
            // nothing to do... in bytes
        }
        else if (strcasecmp(endptr, "k") == 0)
        {
            value *= 1024;
        }
        else if (strcasecmp(endptr, "m") == 0)
        {
            value *= 1024;
            value *= 1024;
        }
        else
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

static json_result_t _config_extract_array(
    json_type_t type,
    const json_union_t* un,
    char*** parameters,
    size_t* parameters_count)
{
    json_result_t ret = JSON_FAILED;

    if ((parameters == NULL) || (parameters_count == NULL))
        CONFIG_RAISE(JSON_BAD_PARAMETER);
    if (type != JSON_TYPE_STRING)
        CONFIG_RAISE(JSON_TYPE_MISMATCH);

    if (*parameters == NULL)
    {
        *parameters_count = 1;
        // malloc enough for null entry at end
        *parameters = malloc((2) * sizeof(char*));
        if (*parameters == NULL)
        {
            CONFIG_RAISE(JSON_OUT_OF_MEMORY);
        }
        else
        {
            (*parameters)[*parameters_count - 1] = un->string;
            (*parameters)[*parameters_count] = NULL;
        }
    }
    else
    {
        // realloc enough for null entry at end
        char** tmp =
            realloc(*parameters, (*parameters_count + 2) * sizeof(char*));
        if (tmp == NULL)
        {
            CONFIG_RAISE(JSON_OUT_OF_MEMORY);
        }
        (*parameters_count)++;
        *parameters = tmp;
        (*parameters)[*parameters_count - 1] = un->string;
        (*parameters)[*parameters_count] = NULL;
    }

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
                ret = _extract_mem_size(type, un, &parsed_data->user_pages);
                if (ret != JSON_OK)
                    CONFIG_RAISE(ret);
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
                ret = _config_extract_array(
                    type,
                    un,
                    &parsed_data->application_parameters,
                    &parsed_data->application_parameters_count);
                if (ret != JSON_OK)
                    CONFIG_RAISE(ret);
            }
            else if (json_match(parser, "EnvironmentVariables") == JSON_OK)
            {
                ret = _config_extract_array(
                    type,
                    un,
                    &parsed_data->enclave_environment_variables,
                    &parsed_data->enclave_environment_variables_count);
                if (ret != JSON_OK)
                    CONFIG_RAISE(ret);
            }
            else if (json_match(parser, "HostEnvironmentVariables") == JSON_OK)
            {
                ret = _config_extract_array(
                    type,
                    un,
                    &parsed_data->host_environment_variables,
                    &parsed_data->host_environment_variables_count);
                if (ret != JSON_OK)
                    CONFIG_RAISE(ret);
            }
            else
            {
                // Ignore everything we dont understand
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

int _parse_config(config_parsed_data_t* parsed_data)
{
    int ret = -1;
    json_parser_t parser;
    const json_parser_options_t options = {1};
    static json_allocator_t allocator = {
        malloc,
        free,
    };

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

    ret = _parse_config(parsed_data);

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
    if (parsed_data->enclave_environment_variables)
        free(parsed_data->enclave_environment_variables);
    if (parsed_data->host_environment_variables)
        free(parsed_data->host_environment_variables);
    if (parsed_data->application_parameters)
        free(parsed_data->application_parameters);
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

    fprintf(out_file, "NumHeapPages=%ld\n", parsed_data->oe_num_heap_pages);

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
