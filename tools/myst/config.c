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

static json_result_t _extract_start_address(
    json_type_t type,
    const json_union_t* un,
    uint64_t* start_address)
{
    json_result_t ret = JSON_FAILED;
    uint64_t value = 0;

    if (start_address == NULL)
        CONFIG_RAISE(JSON_FAILED);

    if (type == JSON_TYPE_INTEGER && un->integer > 0)
        value = (uint64_t)un->integer; // number in bytes
    else
        CONFIG_RAISE(JSON_TYPE_MISMATCH);

    if (value % PAGE_SIZE) // check if aligned to PAGE_SIZE
        CONFIG_RAISE(JSON_REASON_VALUE);

    *start_address = value;

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
            else if (json_match(parser, "CreateZeroBaseEnclave") == JSON_OK)
            {
                if ((type == JSON_TYPE_BOOLEAN) && un->boolean)
                {
                    parsed_data->oe_create_zero_base = true;
                }
                else if (type == JSON_TYPE_BOOLEAN)
                {
                    parsed_data->oe_create_zero_base = false;
                }
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "EnclaveStartAddress") == JSON_OK)
            {
                ret = _extract_start_address(
                    type, un, &parsed_data->oe_start_address);
                if (ret != JSON_OK)
                    CONFIG_RAISE(ret);
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
            else if (json_match(parser, "MainStackSize") == JSON_OK)
            {
                uint64_t main_stack_pages = 0;
                ret = _extract_mem_size(type, un, &main_stack_pages);
                if (ret != JSON_OK)
                    CONFIG_RAISE(ret);
                parsed_data->main_stack_size = main_stack_pages * PAGE_SIZE;
            }
            else if (json_match(parser, "ThreadStackSize") == JSON_OK)
            {
                uint64_t thread_stack_pages = 0;
                ret = _extract_mem_size(type, un, &thread_stack_pages);
                if (ret != JSON_OK)
                    CONFIG_RAISE(ret);
                parsed_data->thread_stack_size = thread_stack_pages * PAGE_SIZE;
            }
            else if (json_match(parser, "MaxAffinityCPUs") == JSON_OK)
            {
                if (type != JSON_TYPE_INTEGER)
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);

                if (un->integer <= 0)
                    CONFIG_RAISE(JSON_OUT_OF_BOUNDS);

                parsed_data->max_affinity_cpus = (size_t)un->integer;
            }
            else if (json_match(parser, "NoBrk") == JSON_OK)
            {
                if (type == JSON_TYPE_BOOLEAN)
                    parsed_data->no_brk = un->boolean;
                else if (type == JSON_TYPE_INTEGER)
                    parsed_data->no_brk = (un->integer == 0) ? false : true;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "ExecStack") == JSON_OK)
            {
                if (type == JSON_TYPE_BOOLEAN)
                    parsed_data->exec_stack = un->boolean;
                else if (type == JSON_TYPE_INTEGER)
                    parsed_data->exec_stack = (un->integer == 0) ? false : true;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
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
            else if (json_match(parser, "ForkMode") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                {
                    if (strcmp(un->string, "none") == 0)
                        parsed_data->fork_mode = myst_fork_none;
                    else if (strcmp(un->string, "pseudo") == 0)
                        parsed_data->fork_mode = myst_fork_pseudo;
                    else if (
                        strcmp(un->string, "pseudo_wait_for_exit_exec") == 0)
                        parsed_data->fork_mode =
                            myst_fork_pseudo_wait_for_exit_exec;
                    else
                        CONFIG_RAISE(JSON_UNKNOWN_VALUE);
                }
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
            else if (json_match(parser, "UnhandledSyscallEnosys") == JSON_OK)
            {
                if (type == JSON_TYPE_BOOLEAN)
                    parsed_data->unhandled_syscall_enosys = un->boolean;
                else if (type == JSON_TYPE_INTEGER)
                    parsed_data->unhandled_syscall_enosys =
                        (un->integer == 0) ? 0 : 1;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "Secret.ID") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->wanted_secrets.secrets[parser->path[0].index]
                        .id = un->string;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "Secret.SrsAddress") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->wanted_secrets.secrets[parser->path[0].index]
                        .srs_addr = un->string;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "Secret.SrsApiVersion") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->wanted_secrets.secrets[parser->path[0].index]
                        .srs_api_ver = un->string;
                else if (type == JSON_TYPE_NULL)
                    parsed_data->wanted_secrets.secrets[parser->path[0].index]
                        .srs_api_ver = NULL;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "Secret.LocalPath") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->wanted_secrets.secrets[parser->path[0].index]
                        .local_path = un->string;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "Secret.ClientLib") == JSON_OK)
            {
                if (type == JSON_TYPE_STRING)
                    parsed_data->wanted_secrets.secrets[parser->path[0].index]
                        .clientlib = un->string;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "Secret.Verbose") == JSON_OK)
            {
                if (type == JSON_TYPE_BOOLEAN)
                    parsed_data->wanted_secrets.secrets[parser->path[0].index]
                        .verbose = un->boolean;
                else if (type == JSON_TYPE_INTEGER && un->integer)
                    parsed_data->wanted_secrets.secrets[parser->path[0].index]
                        .verbose = un->integer;
                else
                    CONFIG_RAISE(JSON_TYPE_MISMATCH);
            }
            else if (json_match(parser, "HostUDS") == JSON_OK)
            {
                if (type == JSON_TYPE_BOOLEAN)
                    parsed_data->host_uds = un->boolean;
                else if (type == JSON_TYPE_INTEGER)
                    parsed_data->host_uds = (un->integer == 0);
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
            else if (json_match(parser, "Secret") == JSON_OK)
            {
                parsed_data->wanted_secrets.secrets =
                    calloc(parser->path[0].size, sizeof(myst_wanted_secret_t));
                parsed_data->wanted_secrets.secrets_count =
                    parser->path[0].size;
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

    /* set default settings */
    {
        parsed_data->oe_num_user_threads = ENCLAVE_MAX_THREADS;
        parsed_data->oe_num_stack_pages = ENCLAVE_STACK_SIZE / PAGE_SIZE;
        parsed_data->oe_create_zero_base = ENCLAVE_CREATE_ZERO_BASE_ENCLAVE;
        parsed_data->oe_start_address = ENCLAVE_START_ADDRESS;
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
    free(parsed_data->wanted_secrets.secrets);

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

    fprintf(
        out_file,
        "CreateZeroBaseEnclave=%d\n",
        parsed_data->oe_create_zero_base);

    if (parsed_data->oe_create_zero_base)
    {
        fprintf(out_file, "StartAddress=%lu\n", parsed_data->oe_start_address);
    }

    /* set CapturePFGPExceptions=1 allows the OE loader to decide whether
     * to enable the feature or not based on the CPU capability */
    fprintf(out_file, "CapturePFGPExceptions=1\n");

    ret = 0;

done:
    if (out_file)
        fclose(out_file);

    return ret;
}
