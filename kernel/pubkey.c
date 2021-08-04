#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <myst/cpio.h>
#include <myst/eraise.h>
#include <myst/panic.h>
#include <myst/pubkey.h>
#include <myst/tcall.h>

int myst_pubkey_verify(
    const void* pubkeys_data,
    size_t pubkeys_size,
    const uint8_t* hash,
    size_t hash_size,
    const uint8_t* signer,
    size_t signer_size,
    const uint8_t* signature,
    size_t signature_size)
{
    int ret = 0;
    const char* p = pubkeys_data;
    const char* end = p + pubkeys_size;

    if (!pubkeys_data)
        ERAISE(-EINVAL);

    if (!hash || !hash_size)
        ERAISE(-EINVAL);

    if (!signer || !signer_size)
        ERAISE(-EINVAL);

    if (!signature || !signature_size)
        ERAISE(-EINVAL);

    /* for each entry in the pubkeys region */
    while (p < end)
    {
        size_t rem = (size_t)(end - p);
        size_t len = strnlen(p, rem);

        if (len == rem)
            ERAISE(-EINVAL);

        if (myst_tcall_verify_signature(
                p,
                hash,
                hash_size,
                signer,
                signer_size,
                signature,
                signature_size) == 0)
        {
            /* success! */
            goto done;
        }

        /* advance to the next public key */
        p += len + 1;
    }

    ret = -EPERM;

done:

    return ret;
}
