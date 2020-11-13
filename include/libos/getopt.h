// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_GETOPT_H
#define _LIBOS_GETOPT_H

#include <stddef.h>

int libos_getopt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg,
    char* err,
    size_t err_size);

#endif /* _LIBOS_GETOPT_H */
