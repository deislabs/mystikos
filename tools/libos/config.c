// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include "config.h"
#include <memory.h>
#include <stdlib.h>
#include "libos/eraise.h"
#include "libos/file.h"

#define CONFIG_RAISE(ERRNUM)                                      \
    do                                                            \
    {                                                             \
        ret = ERRNUM;                                             \
        libos_eraise(__FILE__, __LINE__, __FUNCTION__, (int)ret); \
        goto done;                                                \
    } while (0)

static json_result_t _config_extract_array(
    json_type_t type,
    const json_union_t* un,
    char*** parameters,
    size_t* parameters_count)
{
    json_result_t ret = JSON_FAILED;

    if ((parameters == NULL) || (parameters_count == NULL))
        ERAISE(JSON_BAD_PARAMETER);
    if (type != JSON_TYPE_STRING)
        ERAISE(JSON_TYPE_MISMATCH);

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
        case JSON_REASON_NAME:
        {
            break;
        }
        case JSON_REASON_VALUE:
        {
            if (parsed_data->oe_config_out_file)
            { // OE Config generation only
                if (json_match(parser, "Debug") == JSON_OK)
                {
                    if (((type == JSON_TYPE_BOOLEAN) && un->boolean) ||
                        ((type == JSON_TYPE_INTEGER) && un->integer))
                    {
                        parsed_data->oe_debug = 1;
                        if (parsed_data->oe_config_out_file)
                            fprintf(
                                parsed_data->oe_config_out_file, "Debug=1\n");
                    }
                    else if (
                        (type == JSON_TYPE_BOOLEAN) ||
                        (type == JSON_TYPE_INTEGER))
                    {
                        parsed_data->oe_debug = 1;
                        if (parsed_data->oe_config_out_file)
                            fprintf(
                                parsed_data->oe_config_out_file, "Debug=0\n");
                    }
                    else
                        CONFIG_RAISE(JSON_FAILED);
                }
                else if (json_match(parser, "NumKernelPages") == JSON_OK)
                {
                    if (type == JSON_TYPE_INTEGER)
                    {
                        parsed_data->oe_num_heap_pages = (uint64_t)un->integer;
                        if (parsed_data->oe_config_out_file)
                            fprintf(
                                parsed_data->oe_config_out_file,
                                "NumHeapPages=%ld\n",
                                un->integer);
                    }
                    else
                        CONFIG_RAISE(JSON_FAILED);
                }
                else if (json_match(parser, "NumStackPages") == JSON_OK)
                {
                    if (type == JSON_TYPE_INTEGER)
                    {
                        parsed_data->oe_num_stack_pages = (uint64_t)un->integer;
                        if (parsed_data->oe_config_out_file)
                            fprintf(
                                parsed_data->oe_config_out_file,
                                "NumStackPages=%ld\n",
                                un->integer);
                    }
                    else
                        CONFIG_RAISE(JSON_FAILED);
                }
                else if (json_match(parser, "NumUserThreads") == JSON_OK)
                {
                    if (type == JSON_TYPE_INTEGER)
                    {
                        parsed_data->oe_num_user_threads =
                            (uint64_t)un->integer;
                        if (parsed_data->oe_config_out_file)
                            fprintf(
                                parsed_data->oe_config_out_file,
                                "NumTCS=%ld\n",
                                un->integer);
                    }
                    else
                        CONFIG_RAISE(JSON_FAILED);
                }
                else if (json_match(parser, "ProductID") == JSON_OK)
                {
                    if (type == JSON_TYPE_INTEGER)
                    {
                        parsed_data->oe_product_id =
                            (unsigned short)un->integer;
                        if (parsed_data->oe_config_out_file)
                            fprintf(
                                parsed_data->oe_config_out_file,
                                "ProductID=%ld\n",
                                un->integer);
                    }
                    else
                        CONFIG_RAISE(JSON_FAILED);
                }
                else if (json_match(parser, "SecurityVersion") == JSON_OK)
                {
                    if (type == JSON_TYPE_INTEGER)
                    {
                        parsed_data->oe_security_version =
                            (unsigned short)un->integer;
                        if (parsed_data->oe_config_out_file)
                            fprintf(
                                parsed_data->oe_config_out_file,
                                "SecurityVersion=%ld\n",
                                un->integer);
                    }
                    else
                        CONFIG_RAISE(JSON_FAILED);
                }
            }

            // LibOS configuration
            if (json_match(parser, "NumUserPages") == JSON_OK)
            {
                if (type == JSON_TYPE_INTEGER)
                    parsed_data->user_pages = un->integer;
                else
                    CONFIG_RAISE(JSON_FAILED);
            }
            else if (json_match(parser, "ApplicationPath") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->application_path = un->string;
                else
                    CONFIG_RAISE(JSON_FAILED);
            }
            else if (json_match(parser, "HostApplicationParameters") == JSON_OK)
            {
                if (type == JSON_TYPE_BOOLEAN)
                    parsed_data->allow_host_parameters = un->boolean;
                else if (type == JSON_TYPE_INTEGER)
                    parsed_data->allow_host_parameters =
                        (un->integer == 0) ? 0 : 1;
                else
                    CONFIG_RAISE(JSON_FAILED);
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
        case JSON_REASON_BEGIN_OBJECT:
        {
            // TODO! Make sure we process depth properly
            break;
        }
        case JSON_REASON_END_OBJECT:
        {
            // TODO! Make sure we process depth properly
            break;
        }
        case JSON_REASON_BEGIN_ARRAY:
        {
            break;
        }
        case JSON_REASON_END_ARRAY:
        {
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

    if (json_parser_init(
            &parser,
            (char*)parsed_data->buffer,
            parsed_data->buffer_length,
            _json_read_callback,
            parsed_data,
            &allocator,
            &options) != JSON_OK)
    {
        CONFIG_RAISE(-1);
    }
    if (json_parser_parse(&parser) != JSON_OK)
    {
        CONFIG_RAISE(-1);
    }

    if (parser.depth != 0)
    {
        CONFIG_RAISE(-1);
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
        CONFIG_RAISE(-1);
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
