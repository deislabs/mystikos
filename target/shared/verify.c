#include <string.h>

#include <myst/eraise.h>
#include <myst/sha256.h>
#include <myst/tcall.h>
#include <oeprivate/rsa.h>
#include <openenclave/bits/sgx/region.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>

int myst_tcall_verify_signature(
    const char* public_key,
    const uint8_t* hash,
    size_t hash_size,
    const uint8_t* signer,
    size_t signer_size,
    const uint8_t* signature,
    size_t signature_size)
{
    int ret = 0;
    oe_rsa_public_key_t key = {0};
    uint8_t buf[4096];
    size_t buf_size = sizeof(buf);
    myst_sha256_t sha256;

    if (!public_key || !hash || !hash_size || !signer || !signer_size ||
        !signature || !signature_size)
    {
        ERAISE(-EINVAL);
    }

    if (signer_size != MYST_SHA256_SIZE)
        ERAISE(-EINVAL);

    if (oe_rsa_public_key_read_pem(
            &key, (const uint8_t*)public_key, strlen(public_key) + 1) != 0)
    {
        ERAISE(-EINVAL);
    }

    if (oe_rsa_public_key_get_modulus(&key, buf, &buf_size) != 0)
        ERAISE(-EINVAL);

    ECHECK(myst_sha256(&sha256, buf, buf_size));

    if (memcmp(sha256.data, signer, MYST_SHA256_SIZE) != 0)
        ERAISE(-EINVAL);

    if (oe_rsa_public_key_verify(
            &key,
            OE_HASH_TYPE_SHA256,
            hash,
            hash_size,
            signature,
            signature_size) != 0)
    {
        oe_rsa_public_key_free(&key);
        ERAISE(-EPERM);
    }

    oe_rsa_public_key_free(&key);

done:
    return ret;
}
