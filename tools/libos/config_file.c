// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <memory.h>
#include <stdlib.h>
#include "config.h"
#include "libos/eraise.h"
#include "libos/file.h"

#define CONFIG_RAISE(ERRNUM)                                      \
    do                                                            \
    {                                                             \
        ret = ERRNUM;                                             \
        libos_eraise(__FILE__, __LINE__, __FUNCTION__, (int)ret); \
        goto done;                                                \
    } while (0)

// From the main config.c file
int _parse_config(config_parsed_data_t* parsed_data);

int parse_config_from_file(
    const char* config_path,
    config_parsed_data_t* parsed_data)
{
    int ret = -1;

    if (libos_load_file(
            config_path,
            (void**)&parsed_data->buffer,
            &parsed_data->buffer_length) != 0)
    {
        CONFIG_RAISE(-1);
    }

    ret = _parse_config(parsed_data);
    if (ret != JSON_OK)
    {
        CONFIG_RAISE(-1);
    }

    if (ret != 0 && parsed_data->buffer)
    {
        free(parsed_data->buffer);
        parsed_data->buffer = NULL;
    }
done:
    return ret;
}