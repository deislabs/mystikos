// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_LOCKFS_H
#define _MYST_LOCKFS_H

#include <myst/fs.h>

int myst_lockfs_wrap(myst_fstype_t* fs, myst_fstype_t** lockfs);

#endif /* _MYST_LOCKFS_H */
