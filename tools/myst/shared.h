// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MYST_SHARED_H
#define _MYST_MYST_SHARED_H

#include <myst/args.h>
#include <myst/kernel.h>
#include <myst/options.h>
#include <myst/regions.h>
#include "config.h"

int myst_expand_size_string_to_ulong(const char* size_string, size_t* size);
bool myst_merge_mount_mapping_and_config(
    myst_mounts_config_t* mounts,
    myst_args_t* mount_mapping);
bool myst_validate_mount_config(myst_mounts_config_t* mounts);

long determine_final_options(
    struct myst_options* cmdline_opts,
    struct myst_final_options* final_opts,
    const myst_args_t* args,
    const myst_args_t* env,
    config_parsed_data_t* parsed_config,
    bool have_config,
    bool tee_debug_mode,
    const char* target_env_var,
    myst_args_t* mount_mappings);

int myst_syslog_level_str_to_int(const char* syslog_level_str);

#endif /* _MYST_MYST_SHARED_H */
