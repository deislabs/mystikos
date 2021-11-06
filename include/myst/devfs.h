// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_DEVFS_H
#define _MYST_DEVFS_H

#include <myst/buf.h>
#include <myst/fs.h>
#include <stdbool.h>

/*
**==============================================================================
**
** devfs lifetime management
**
**==============================================================================
*/

int devfs_setup();

int devfs_teardown();

int devfs_get_pts_id(myst_file_t* file, int* id);

bool devfs_is_pty_pts_device(myst_file_t* file);

#endif /* _MYST_DEVFS_H */
