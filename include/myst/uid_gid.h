// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <myst/kernel.h>
#include <sys/types.h>

void myst_set_host_uid_gid_mappings(
    myst_host_enc_uid_gid_mappings* host_enc_uid_gid_mappings);
uid_t myst_enc_uid_to_host(uid_t euid);
gid_t myst_enc_gid_to_host(gid_t egid);

uid_t myst_host_uid_to_enc(uid_t uid);
uid_t myst_host_gid_to_enc(gid_t gid);
