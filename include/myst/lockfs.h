// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_LOCKFS_H
#define _MYST_LOCKFS_H

#include <myst/fs.h>

int myst_lockfs_init(myst_fs_t* fs, myst_fs_t** lockfs);

myst_fs_t* myst_lockfs_target(myst_fs_t* fs);

#endif /* _MYST_LOCKFS_H */
