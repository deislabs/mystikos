// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <mbedtls/sha256.h>

#include <myst/sha256.h>
#include <myst/eraise.h>
#include <myst/defs.h>

MYST_STATIC_ASSERT(sizeof(mbedtls_sha256_context) <= sizeof(myst_sha256_ctx_t));

int myst_sha256_start(myst_sha256_ctx_t* ctx)
{
    int ret = 0;
    mbedtls_sha256_context* mctx = (mbedtls_sha256_context*)ctx;

    if (!mctx)
        ERAISE(-EINVAL);

    mbedtls_sha256_init(mctx);

    if (mbedtls_sha256_starts_ret(mctx, 0) != 0)
        ERAISE(-EINVAL);

done:
    return ret;
}

int myst_sha256_update(myst_sha256_ctx_t* ctx, const void* data, size_t size)
{
    int ret = 0;
    mbedtls_sha256_context* mctx = (mbedtls_sha256_context*)ctx;

    if (!mctx)
        ERAISE(-EINVAL);

    if (mbedtls_sha256_update_ret(mctx, data, size) != 0)
        ERAISE(-EINVAL);

done:
    return ret;
}

int myst_sha256_finish(myst_sha256_ctx_t* ctx, myst_sha256_t* sha256)
{
    int ret = 0;
    mbedtls_sha256_context* mctx = (mbedtls_sha256_context*)ctx;

    if (!mctx)
        ERAISE(-EINVAL);

    if (mbedtls_sha256_finish_ret(mctx, sha256->data) != 0)
        ERAISE(-EINVAL);

    mbedtls_sha256_free(mctx);

done:
    return ret;
}

int myst_sha256(myst_sha256_t* sha256, const void* data, size_t size)
{
    int ret = 0;
    myst_sha256_ctx_t ctx;

    if (!sha256 || !data)
        ERAISE(-EINVAL);

    ECHECK(myst_sha256_start(&ctx));
    ECHECK(myst_sha256_update(&ctx, data, size));
    ECHECK(myst_sha256_finish(&ctx, sha256));

done:
    return ret;
}
