// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_HOST_STRACE_H
#define _MYST_HOST_STRACE_H

#include <myst/options.h>

int myst_parse_strace_config(
    int* argc,
    const char** argv,
    myst_strace_config_t* strace_config);

#endif // _MYST_HOST_STRACE_H
