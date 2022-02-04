// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SHMFS_H
#define _MYST_SHMFS_H

#include <myst/buf.h>
#include <myst/fs.h>

/*
**==============================================================================
**
** shmfs lifetime management
**
**==============================================================================
*/

int shmfs_setup();

int shmfs_teardown();

#endif /* _MYST_SHMFS_H */
