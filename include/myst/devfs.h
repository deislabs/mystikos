// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_DEVFS_H
#define _MYST_DEVFS_H

#include <myst/buf.h>
#include <myst/fs.h>
#include <stdbool.h>

typedef enum myst_vfile_populate_time
{
    AT_NONE,
    AT_OPEN,
    AT_READ
} myst_vfile_populate_time_t;

/*
**==============================================================================
**
** devfs lifetime management
**
**==============================================================================
*/

int devfs_setup();

int devfs_teardown();

#endif /* _MYST_DEVFS_H */
