// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MYST_SHARED_H
#define _MYST_MYST_SHARED_H

#include <myst/regions.h>

#define ENCLAVE_MAX_THREADS 1024

int myst_expand_size_string_to_ulong(const char* size_string, size_t* size);

#endif /* _MYST_MYST_SHARED_H */
