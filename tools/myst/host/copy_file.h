// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TOOLS_MYST_HOST_COPY_FILE_H
#define _MYST_TOOLS_MYST_HOST_COPY_FILE_H

#include <stddef.h>

#include <myst/args.h>

// get which host files to copy
int get_host_file_copy_list(myst_args_t* copy_host_files);
void free_host_file_copy_list();

#endif /* _MYST_TOOLS_MYST_HOST_COPY_FILE_H */
