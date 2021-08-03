// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_HOSTFS_H
#define _MYST_HOSTFS_H

#include <myst/fs.h>

int myst_init_hostfs(myst_fs_t** fs_out);

bool myst_is_hostfs(const myst_fs_t* fs);

#endif /* _MYST_HOSTFS_H */
