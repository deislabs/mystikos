// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <assert.h>
#include <mbedtls/aes.h>
#include <mbedtls/aes.h>
#include <mbedtls/config.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <string.h>
#include <openenclave/enclave.h>

static const char text[64] = "abcdefghijklmnopqrstuvwxyz01234";

void hexdump(const void* data, size_t size)
{
    const uint8_t* p = data;
    size_t n = size;

    while (n--)
        printf("%02x", *p++);

    printf("\n");
}

static int crypt(
    bool encrypt,
    const void* key,
    size_t key_size,
    uint8_t iv[16],
    const void* input,
    size_t input_size,
    void* output)
{
    int ret = 0;
    mbedtls_aes_context ctx;

    mbedtls_aes_init(&ctx);

    if (encrypt)
    {
        if ((ret = mbedtls_aes_setkey_enc(&ctx, key, key_size * 8)) != 0)
            goto done;
    }
    else
    {
        if ((ret = mbedtls_aes_setkey_dec(&ctx, key, key_size * 8)) != 0)
            goto done;
    }

    if ((ret = mbedtls_aes_crypt_cbc(
        &ctx,
        encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
        input_size,
        iv,
        input,
        output)) != 0)
    {
        goto done;
    }

done:
    mbedtls_aes_free(&ctx);

    return ret;
}

void test_sealing(void)
{
    oe_result_t result;
    uint8_t* key = NULL;
    size_t key_size = 0;
    unsigned char iv[16];
    char cipher[sizeof(text)];
    char plain[sizeof(text)];

    result = oe_get_seal_key_by_policy_v2(
        OE_SEAL_POLICY_UNIQUE,
        &key,
        &key_size,
        NULL,
        NULL);
    assert(result == OE_OK);

    memset(iv, 0xdd, sizeof(iv));

    if (crypt(
        true,
        key,
        key_size,
        iv,
        text,
        sizeof(text),
        cipher) != 0)
    {
        assert(false);
    }

    memset(iv, 0xdd, sizeof(iv));

    if (crypt(
        false,
        key,
        key_size,
        iv,
        cipher,
        sizeof(text),
        plain) != 0)
    {
        assert(false);
    }

    assert(memcmp(text, plain, sizeof(text)) == 0);
    oe_free_key(key, key_size, NULL, 0);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    const char* target = getenv("MYST_TARGET");

    if (strcmp(target, "sgx") == 0)
        test_sealing();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
