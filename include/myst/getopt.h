// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_GETOPT_H
#define _MYST_GETOPT_H

#include <stddef.h>

int myst_getopt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg,
    char* err,
    size_t err_size);

#endif /* _MYST_GETOPT_H */
