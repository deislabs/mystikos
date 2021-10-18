// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_ID_H
#define _MYST_ID_H

#include <unistd.h>

#define MYST_DEFAULT_UID (uid_t)0
#define MYST_DEFAULT_GID (gid_t)0

#define MYST_RESUID_INITIALIZER \
    {                           \
        -1, -1, -1              \
    }
#define MYST_RESGID_INITIALIZER \
    {                           \
        -1, -1, -1              \
    }

typedef struct myst_resuid
{
    uid_t ruid; /* real user-id */
    uid_t euid; /* effective user-id */
    uid_t suid; /* saved set-user-id */
} myst_resuid_t;

typedef struct myst_resgid
{
    gid_t rgid; /* real group-id */
    gid_t egid; /* effective group-id */
    gid_t sgid; /* saved set-group-id */
} myst_resgid_t;

/* set the effective user-id and group-id and get the old identity */
long myst_change_identity(
    uid_t euid,
    gid_t egid,
    myst_resuid_t* resuid,
    myst_resgid_t* resgid);

/* restore the identity to resuid and resgid */
long myst_restore_identity(
    const myst_resuid_t* resuid,
    const myst_resgid_t* resgid);

#endif /* _MYST_ID_H */
