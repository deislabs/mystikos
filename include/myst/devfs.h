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

#endif /* _MYST_DEVFS_H */
