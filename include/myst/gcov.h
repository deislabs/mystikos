// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_GCOV_H
#define _MYST_GCOV_H

#include <myst/libc.h>
#include <stdio.h>

int gcov_init_libc(libc_t* libc, FILE* stderr_stream);

#endif /* _MYST_GCOV_H */
