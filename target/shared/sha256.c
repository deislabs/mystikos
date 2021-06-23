#include <errno.h>

#ifdef USE_MBEDTLS
#include <mbedtls/sha256.h>
#else
#include <openssl/sha.h>
#endif

#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/sha256.h>

#ifdef USE_MBEDTLS
typedef mbedtls_sha256_context context_t;
#else
typedef SHA256_CTX context_t;
#endif

MYST_STATIC_ASSERT(sizeof(context_t) <= sizeof(myst_sha256_ctx_t));

int myst_sha256_start(myst_sha256_ctx_t* ctx)
{
    int ret = 0;

    if (!ctx)
        ERAISE(-EINVAL);

#ifdef USE_MBEDTLS
    mbedtls_sha256_init((context_t*)ctx);

    if (mbedtls_sha256_starts_ret((context_t*)ctx, 0) != 0)
        ERAISE(-EINVAL);
#else
    if (!SHA256_Init((context_t*)ctx))
        ERAISE(-ENOSYS);
#endif

done:
    return ret;
}

int myst_sha256_update(myst_sha256_ctx_t* ctx, const void* data, size_t size)
{
    int ret = 0;

    if (!ctx)
        ERAISE(-EINVAL);

#ifdef USE_MBEDTLS
    if (mbedtls_sha256_update_ret((context_t*)ctx, data, size) != 0)
        ERAISE(-EINVAL);
#else
    if (!SHA256_Update((context_t*)ctx, data, size))
        ERAISE(-ENOSYS);
#endif

done:
    return ret;
}

int myst_sha256_finish(myst_sha256_ctx_t* ctx, myst_sha256_t* sha256)
{
    int ret = 0;

    if (!ctx)
        ERAISE(-EINVAL);

#ifdef USE_MBEDTLS
    if (mbedtls_sha256_finish_ret((context_t*)ctx, sha256->data) != 0)
        ERAISE(-EINVAL);
#else
    if (!SHA256_Final(sha256->data, (SHA256_CTX*)ctx))
        ERAISE(-ENOSYS);
#endif

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
