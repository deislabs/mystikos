// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_PROXYFS_H
#define _MYST_PROXYFS_H

#include <myst/fs.h>

int myst_proxyfile_wrap(uint64_t file_cookie, myst_file_t** file_out);

int myst_proxyfs_wrap(uint64_t fs_cookie, myst_fs_t** fs_out);

bool myst_is_proxyfs(const myst_fs_t* fs);

int myst_proxy_mount_resolve(
    const char* path,
    char suffix[PATH_MAX],
    myst_fs_t** fs_out);

#endif /* _MYST_PROXYFS_H */
