// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_PROCFS_H
#define _MYST_PROCFS_H

#include <myst/ramfs.h>

int create_proc_root_entries();

/*
**==============================================================================
**
** procfs lifetime management
**
**==============================================================================
*/

int procfs_setup();

int procfs_cleanup();

#endif /* _MYST_PROCFS_H */
