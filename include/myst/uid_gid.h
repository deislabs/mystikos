// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#ifndef _MYST_UID_GID_H
#define _MYST_UID_GID_H

#include <sys/types.h>

#define MAX_ID_MAPPINGS 8
typedef struct _myst_host_enc_uid_mapping
{
    uid_t host_uid;
    uid_t enc_uid;
} myst_host_enc_uid_mapping;

typedef struct _myst_host_enc_gid_mapping
{
    gid_t host_gid;
    gid_t enc_gid;
} myst_host_enc_gid_mapping;

typedef struct _myst_host_enc_uid_gid_mapping
{
    myst_host_enc_uid_mapping uid_mappings[MAX_ID_MAPPINGS];
    int num_uid_mappings;
    myst_host_enc_gid_mapping gid_mappings[MAX_ID_MAPPINGS];
    int num_gid_mappings;
} myst_host_enc_uid_gid_mappings;

void myst_copy_host_uid_gid_mappings(
    myst_host_enc_uid_gid_mappings* host_enc_uid_gid_mappings);

int myst_enc_uid_to_host(uid_t enc_uid, uid_t* host_uid);
int myst_enc_gid_to_host(gid_t enc_gid, gid_t* host_gid);

int myst_host_uid_to_enc(uid_t host_uid, uid_t* enc_uid);
int myst_host_gid_to_enc(gid_t host_gid, gid_t* enc_gid);

int check_thread_group_membership(gid_t group);

long myst_valid_uid_against_passwd_file(uid_t uid);
long myst_valid_gid_against_group_file(gid_t gid);

#endif /* _MYST_UID_GID_H */
