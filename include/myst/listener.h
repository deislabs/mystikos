
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_LISTENER_H
#define _MYST_LISTENER_H

#include <myst/defs.h>
#include <myst/fs.h>
#include <myst/types.h>

int myst_ping_listener(void);

int myst_shutdown_listener(void);

long myst_listener_open(
    const char* pathname,
    int flags,
    mode_t mode,
    myst_fs_t** fs_out,
    myst_file_t** file_out);

#endif /* _MYST_LISTENER_H */
