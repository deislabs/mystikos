// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MYST_SHARED_H
#define _MYST_MYST_SHARED_H

#include <myst/kernel.h>
#include <myst/options.h>
#include <myst/regions.h>

int myst_expand_size_string_to_ulong(const char* size_string, size_t* size);
bool myst_merge_mount_mapping_and_config(
    myst_mounts_config_t* mounts,
    myst_mount_mapping_t* mount_mapping);
bool myst_validate_mount_config(myst_mounts_config_t* mounts);

#endif /* _MYST_MYST_SHARED_H */
