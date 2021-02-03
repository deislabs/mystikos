// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_LUKS_H
#define _MYST_LUKS_H

#include <stdint.h>

#define LUKS_SALT_SIZE 32
#define LUKS_SECTOR_SIZE 512
#define LUKS_MAGIC_SIZE 6
#define LUKS_CIPHER_NAME_SIZE 32
#define LUKS_CIPHER_MODE_SIZE 32
#define LUKS_HASH_SPEC_SIZE 32
#define LUKS_DIGEST_SIZE 20
#define LUKS_UUID_STRING_SIZE 40
#define LUKS_SLOTS_SIZE 8

typedef struct luks_keyslot
{
    uint32_t active;
    uint32_t iterations;
    uint8_t salt[LUKS_SALT_SIZE];
    uint32_t key_material_offset;
    uint32_t stripes;
} luks_keyslot_t;

typedef struct
{
    uint8_t magic[LUKS_MAGIC_SIZE];
    uint16_t version;
    char cipher_name[LUKS_CIPHER_NAME_SIZE];
    char cipher_mode[LUKS_CIPHER_MODE_SIZE];
    char hash_spec[LUKS_HASH_SPEC_SIZE];
    uint32_t payload_offset;
    uint32_t key_bytes;
    uint8_t mk_digest[LUKS_DIGEST_SIZE];
    uint8_t mk_digest_salt[LUKS_SALT_SIZE];
    uint32_t mk_digest_iter;
    char uuid[LUKS_UUID_STRING_SIZE];
    luks_keyslot_t slots[LUKS_SLOTS_SIZE];
} luks_phdr_t;

_Static_assert(sizeof(luks_phdr_t) == 592, "");

int myst_luks_encrypt(
    const luks_phdr_t* phdr,
    const void* key,
    const uint8_t* data_in,
    uint8_t* data_out,
    size_t data_size,
    uint64_t sector);

int myst_luks_decrypt(
    const luks_phdr_t* phdr,
    const void* key,
    const uint8_t* data_in,
    uint8_t* data_out,
    size_t data_size,
    uint64_t sector);

#endif /* _MYST_LUKS_H */
