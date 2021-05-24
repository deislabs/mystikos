// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <myst/kernel.h>
#include <sys/types.h>

void myst_set_host_uid_gid_mappings(
    myst_host_enc_uid_gid_mappings* host_enc_uid_gid_mappings);

int myst_enc_uid_to_host(uid_t enc_uid, uid_t* host_uid);
int myst_enc_gid_to_host(gid_t enc_gid, gid_t* host_gid);

int myst_host_uid_to_enc(uid_t host_uid, uid_t* enc_uid);
int myst_host_gid_to_enc(gid_t host_gid, gid_t* enc_gid);

int check_thread_group_membership(gid_t group);