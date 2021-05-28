// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <memory.h>
#include <stdlib.h>
#include "config.h"
#include "myst/file.h"

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

int parse_config_from_file(
    const char* config_path,
    config_parsed_data_t* parsed_data)
{
    int ret = -1;

    if (myst_load_file(
            config_path,
            (void**)&parsed_data->buffer,
            &parsed_data->buffer_length) != 0)
    {
        CONFIG_RAISE(JSON_FAILED);
    }

    ret = parse_config(parsed_data);
    if (ret != JSON_OK)
    {
        CONFIG_RAISE(ret);
    }

    if (ret != 0 && parsed_data->buffer)
    {
        free(parsed_data->buffer);
        parsed_data->buffer = NULL;
    }
done:
    return ret;
}
