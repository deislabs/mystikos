#include <errno.h>
#include <openssl/sha.h>

#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/sha256.h>

MYST_STATIC_ASSERT(sizeof(SHA256_CTX) <= sizeof(myst_sha256_ctx_t));

int myst_sha256_start(myst_sha256_ctx_t* ctx)
{
    int ret = 0;

    if (!ctx)
        ERAISE(-EINVAL);

    if (!SHA256_Init((SHA256_CTX*)ctx))
        ERAISE(-ENOSYS);

done:
    return ret;
}

int myst_sha256_update(myst_sha256_ctx_t* ctx, const void* data, size_t size)
{
    int ret = 0;

    if (!ctx)
        ERAISE(-EINVAL);

    if (!SHA256_Update((SHA256_CTX*)ctx, data, size))
        ERAISE(-ENOSYS);

done:
    return ret;
}

int myst_sha256_finish(myst_sha256_ctx_t* ctx, myst_sha256_t* sha256)
{
    int ret = 0;

    if (!ctx)
        ERAISE(-EINVAL);

    if (!SHA256_Final(sha256->data, (SHA256_CTX*)ctx))
        ERAISE(-ENOSYS);

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
