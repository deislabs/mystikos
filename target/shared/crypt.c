#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <string.h>

#include <myst/crypt.h>
#include <myst/eraise.h>
#include <myst/sha256.h>

#define IV_SIZE 16

/* initialization vector */
struct iv
{
    uint64_t counter;
    uint64_t padding;
};

static int _crypt(
    mbedtls_operation_t op, /* MBEDTLS_ENCRYPT or MBEDTLS_DECRYPT */
    const myst_key_512_t* key,
    const uint8_t* data_in,
    uint8_t* data_out,
    size_t data_size,
    uint64_t counter)
{
    int ret = 0;
    const mbedtls_cipher_info_t* ci;
    struct context_wrapper
    {
        uint64_t header;
        mbedtls_cipher_context_t ctx;
        uint64_t footer1;
        uint64_t footer2;
    };
    struct context_wrapper wrapper;
    struct iv iv = {counter, 0};
    const size_t key_bits = sizeof(myst_key_512_t) * 8;
    size_t olen;

    // mbedtls_cipher_init() writes 8 bytes past the end of its parameter. At
    // first it seemed that this was due to a header/library mismatch (but this
    // turns out not to be the case: both are using OE mbedtls artifacts). To
    // work around this, mbedtls_cipher_context_t is wrapped in a structure and
    // sandwhiched between one header and two footers. We verify below that the
    // first header and the second footer have not been disrupted. The first
    // footer is disrupted in all cases we have observed so far.
    {
        const uint64_t magic = 0x7b800f55ffb7403e;
        wrapper.header = magic;
        wrapper.footer1 = magic;
        wrapper.footer2 = magic;
        mbedtls_cipher_init(&wrapper.ctx);

        if (wrapper.header != magic)
            ERAISE(-ENOSYS);

        if (wrapper.footer2 != magic)
            ERAISE(-ENOSYS);
    }

    if (!(ci = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_XTS)))
        ERAISE(-ENOSYS);

    if (mbedtls_cipher_setup(&wrapper.ctx, ci) != 0)
        ERAISE(-ENOSYS);

    if (mbedtls_cipher_setkey(&wrapper.ctx, key->data, (int)key_bits, op) != 0)
        ERAISE(-ENOSYS);

    if (mbedtls_cipher_crypt(
            &wrapper.ctx,
            (const uint8_t*)&iv, /* iv */
            IV_SIZE,             /* iv_size */
            data_in,             /* input */
            data_size,           /* ilen */
            data_out,            /* output */
            &olen) != 0)         /* olen */
    {
        ERAISE(-ENOSYS);
    }

    if (olen != data_size)
        ERAISE(-ENOSYS);

done:
    mbedtls_cipher_free(&wrapper.ctx);

    return ret;
}

int myst_encrypt_aes_256_xts(
    const myst_key_512_t* key,
    const void* data_in,
    void* data_out,
    size_t data_size,
    uint64_t counter)
{
    return _crypt(MBEDTLS_ENCRYPT, key, data_in, data_out, data_size, counter);
}

int myst_decrypt_aes_256_xts(
    const myst_key_512_t* key,
    const void* data_in,
    void* data_out,
    size_t data_size,
    uint64_t counter)
{
    return _crypt(MBEDTLS_DECRYPT, key, data_in, data_out, data_size, counter);
}
