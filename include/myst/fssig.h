// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_FSSIG_H
#define _MYST_FSSIG_H

#include <stdint.h>
#include <myst/defs.h>
#include <myst/sha256.h>

#define MYST_FSSIG_MAGIC 0xf55198a153624d38

#define MYST_FSSIG_VERSION 1

/* large enough for a 8192-bit key/signature */
#define MYST_MAX_SIGNATURE_SIZE 1024

/* the file-system signature structure */
typedef struct myst_fssig
{
    /* the magic number (must be MYST_FSSIG_MAGIC) */
    uint64_t magic;

    /* the version number (must be MYST_FSSIG_VERSION) */
    uint64_t version;

    /* offset in bytes of the hash tree (from start of file system image) */
    uint64_t hash_offset;

    /* SHA-256 root hash (of the hash tree) */
    uint8_t root_hash[MYST_SHA256_SIZE];

    /* SHA-256 hash of the exponent of the signer's key */
    uint8_t signer[MYST_SHA256_SIZE];

    /* the signature */
    uint8_t signature[MYST_MAX_SIGNATURE_SIZE];

    /* the size of the signature in bytes */
    uint64_t signature_size;

    /* padding */
    uint8_t padding[2976];
}
myst_fssig_t;

MYST_STATIC_ASSERT(sizeof(myst_fssig_t) == 4096);

/* load the file-system signature struct from the given host file */
int myst_load_fssig(const char* path, myst_fssig_t* fssig);

#endif /* _MYST_FSSIG_H */
