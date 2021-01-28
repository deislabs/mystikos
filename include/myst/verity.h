// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_VERITY_H
#define _MYST_VERITY_H

#include <myst/defs.h>
#include <stdint.h>

#define MYST_VERITY_MAX_SALT_SIZE 256

MYST_PACK_BEGIN
typedef struct myst_verity_sb
{
    /* (0) "verity\0\0" */
    uint8_t signature[8];

    /* (8) superblock version, 1 */
    uint32_t version;

    /* (12) 0 - Chrome OS, 1 - normal */
    uint32_t hash_type;

    /* (16) UUID of hash device */
    uint8_t uuid[16];

    /* (32) Name of the hash algorithm (e.g., sha256) */
    char algorithm[32];

    /* (64) The data block size in bytes */
    uint32_t data_block_size;

    /* (68) The hash block size in bytes */
    uint32_t hash_block_size;

    /* (72) The number of data blocks */
    uint64_t data_blocks;

    /* (80) Size of the salt */
    uint16_t salt_size;

    /* (82) Padding */
    uint8_t _pad1[6];

    /* (88) The salt */
    uint8_t salt[MYST_VERITY_MAX_SALT_SIZE];

    /* Padding */
    uint8_t _pad2[168];
} myst_verity_sb_t;
MYST_PACK_END

MYST_STATIC_ASSERT(sizeof(myst_verity_sb_t) == 512);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_verity_sb_t, signature) == 0);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_verity_sb_t, version) == 8);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_verity_sb_t, hash_type) == 12);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_verity_sb_t, uuid) == 16);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_verity_sb_t, algorithm) == 32);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_verity_sb_t, data_block_size) == 64);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_verity_sb_t, hash_block_size) == 68);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_verity_sb_t, data_blocks) == 72);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_verity_sb_t, salt_size) == 80);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_verity_sb_t, _pad1) == 82);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_verity_sb_t, salt) == 88);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_verity_sb_t, _pad2) == 344);

#endif /* _MYST_VERITY_H */
