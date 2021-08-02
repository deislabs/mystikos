// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_HOSTFILE_H
#define _MYST_HOSTFILE_H

#include <stddef.h>

#include <myst/defs.h>

// Load a file from the host file system (zero-terminates data but does
// not include the terminator in the size)
int myst_load_host_file(const char* path, void** data, size_t* size);

#endif /* _MYST_HOSTFILE_H */
