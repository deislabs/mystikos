// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_PROCFS_H
#define _MYST_PROCFS_H

#include <fcntl.h>

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

int procfs_teardown();

/* Cleanup /proc/[pid] entries */
int procfs_pid_cleanup(pid_t pid);

#endif /* _MYST_PROCFS_H */
