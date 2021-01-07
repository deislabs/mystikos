// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_CONF_H
#define _MYST_CONF_H

#include <stddef.h>

typedef struct myst_conf_err
{
    char buf[256];
} myst_conf_err_t;

typedef int (*myst_conf_callback_t)(
    const char* name,
    const char* value,
    void* callback_data,
    myst_conf_err_t* err);

int myst_conf_parse(
    const char* text,
    size_t text_size,
    myst_conf_callback_t callback,
    void* callback_data,
    size_t* error_line,
    myst_conf_err_t* err);

#endif /* _MYST_CONF_H */
