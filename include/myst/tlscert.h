// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TLSCERT_H
#define _MYST_TLSCERT_H

#include <myst/fs.h>

int myst_init_tls_credential_files(
    const char* want_tls_creds,
    myst_fs_t* fs,
    myst_fstype_t fstype);

#endif /* _MYST_TLSCERT_H */