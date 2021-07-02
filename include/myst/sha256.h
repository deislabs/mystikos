// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SHA256_H
#define _MYST_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define MYST_SHA256_SIZE 32

#define MYST_SHA256_ASCII_LENGTH (2 * MYST_SHA256_SIZE)

#define MYST_SHA256_ASCII_SIZE (MYST_SHA256_ASCII_LENGTH + 1)

typedef struct myst_sha256_ctx
{
    uint64_t opaque[16];
} myst_sha256_ctx_t;

typedef struct myst_sha256
{
    uint8_t data[MYST_SHA256_SIZE];
} myst_sha256_t;

int myst_sha256(myst_sha256_t* sha256, const void* data, size_t size);

int myst_sha256_start(myst_sha256_ctx_t* ctx);

int myst_sha256_update(myst_sha256_ctx_t* ctx, const void* data, size_t size);

int myst_sha256_finish(myst_sha256_ctx_t* ctx, myst_sha256_t* sha256);

#endif /* _MYST_SHA256_H */
