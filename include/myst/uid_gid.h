// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <myst/kernel.h>
#include <sys/types.h>

void myst_set_host_uid_gid_mapping(
    myst_host_enc_id_mapping host_enc_id_mapping);
uid_t myst_enc_uid_to_host(uid_t euid);
gid_t myst_enc_gid_to_host(gid_t egid);
