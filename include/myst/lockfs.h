// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_LOCKFS_H
#define _MYST_LOCKFS_H

#include <stdbool.h>

#include <myst/fs.h>

int myst_lockfs_init(myst_fs_t* fs, myst_fs_t** lockfs);

myst_fs_t* myst_lockfs_target(myst_fs_t* fs);

bool myst_is_lockfs(const myst_fs_t* fs);

void myst_lockfs_lock(void);

void myst_lockfs_unlock(void);

#endif /* _MYST_LOCKFS_H */
