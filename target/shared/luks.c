#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <string.h>

#include <myst/luks.h>

#define LUKS_IV_SIZE 16

#define LUKS_CIPHER_NAME_AES "aes"
#define LUKS_CIPHER_MODE_ECB "ecb"
#define LUKS_CIPHER_MODE_CBC_PLAIN "cbc-plain"
#define LUKS_CIPHER_MODE_XTS_PLAIN64 "xts-plain64"

#define SHA256_SIZE 32

static int _hash(const void* data, size_t size, uint8_t hash[SHA256_SIZE])
{
    int ret = -1;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    if (mbedtls_sha256_starts_ret(&ctx, 0) != 0)
        goto done;

    if (mbedtls_sha256_update_ret(&ctx, data, size) != 0)
        goto done;

    if (mbedtls_sha256_finish_ret(&ctx, hash) != 0)
        goto done;

    ret = 0;

done:
    mbedtls_sha256_free(&ctx);
    return ret;
}

static const mbedtls_cipher_info_t* _get_cipher_info(const luks_phdr_t* phdr)
{
    const mbedtls_cipher_info_t* ret = NULL;
    mbedtls_cipher_type_t cipher_type;
    uint32_t key_bits;

    if (!phdr)
        goto done;

    /* ATTN-C: Only AES is supported */
    if (strcmp(phdr->cipher_name, LUKS_CIPHER_NAME_AES) != 0)
        return NULL;

    key_bits = phdr->key_bytes * 8;

    if (strcmp(phdr->cipher_mode, LUKS_CIPHER_MODE_ECB) == 0)
    {
        switch (key_bits)
        {
            case 128:
                cipher_type = MBEDTLS_CIPHER_AES_128_ECB;
                break;
            case 256:
                cipher_type = MBEDTLS_CIPHER_AES_256_ECB;
                break;
            default:
                goto done;
        }
    }
    else if (strcmp(phdr->cipher_mode, LUKS_CIPHER_MODE_CBC_PLAIN) == 0)
    {
        switch (key_bits)
        {
            case 128:
                cipher_type = MBEDTLS_CIPHER_AES_128_CBC;
                break;
            case 256:
                cipher_type = MBEDTLS_CIPHER_AES_256_CBC;
                break;
            default:
                goto done;
        }
    }
    else if (strcmp(phdr->cipher_mode, LUKS_CIPHER_MODE_XTS_PLAIN64) == 0)
    {
        /* XTS splits the key in half */
        switch (key_bits / 2)
        {
            case 128:
                cipher_type = MBEDTLS_CIPHER_AES_128_XTS;
                break;
            case 256:
                cipher_type = MBEDTLS_CIPHER_AES_256_XTS;
                break;
            default:
                goto done;
        }
    }
    else
    {
        return NULL;
    }

    ret = mbedtls_cipher_info_from_type(cipher_type);

done:
    return ret;
}

static int _gen_iv(
    const luks_phdr_t* phdr,
    uint64_t sector,
    uint8_t* iv,
    const uint8_t* key)
{
    int ret = -1;
    uint8_t hash[SHA256_SIZE];
    mbedtls_aes_context aes_ctx;

    mbedtls_aes_init(&aes_ctx);

    if (iv)
        memset(iv, 0, LUKS_IV_SIZE);

    if (!phdr || !iv || !key)
        goto done;

    if (strcmp(LUKS_CIPHER_MODE_ECB, phdr->cipher_mode) == 0)
    {
        memset(iv, 0, LUKS_IV_SIZE);
        ret = 0;
        goto done;
    }

    if (strcmp(LUKS_CIPHER_MODE_CBC_PLAIN, phdr->cipher_mode) == 0)
    {
        /* Assume little endian where the sector number is captured */
        memcpy(iv, &sector, sizeof(uint32_t));
        ret = 0;
        goto done;
    }

    if (strcmp(LUKS_CIPHER_MODE_XTS_PLAIN64, phdr->cipher_mode) == 0)
    {
        memcpy(iv, &sector, sizeof(uint64_t));
        ret = 0;
        goto done;
    }

    /* Compute the hash of the key */
    if (_hash(key, phdr->key_bytes, hash) != 0)
        goto done;

    /* Use the SHA256-generated hash as the key */
    if (mbedtls_aes_setkey_enc(&aes_ctx, hash, sizeof(hash) * 8) != 0)
    {
        goto done;
    }

    /* Encrypt the sector number with the generated key hash to get the IV */
    {
        uint8_t buf[LUKS_IV_SIZE];

        memset(buf, 0, sizeof(buf));
        memcpy(buf, &sector, sizeof(uint64_t));

        /* Encrypt the buffer with the hash of the key, yielding the IV. */
        if (mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, buf, iv) != 0)
            goto done;
    }

    ret = 0;

done:

    mbedtls_aes_free(&aes_ctx);

    return ret;
}

static int _crypt(
    const luks_phdr_t* phdr,
    mbedtls_operation_t op, /* MBEDTLS_ENCRYPT or MBEDTLS_DECRYPT */
    const void* key,
    const uint8_t* data_in,
    uint8_t* data_out,
    size_t data_size,
    uint64_t sector)
{
    int ret = -1;
    const mbedtls_cipher_info_t* ci;
    mbedtls_cipher_context_t ctx;
    uint8_t iv[LUKS_IV_SIZE];
    uint64_t i;
    uint64_t iters;
    uint64_t block_size;

    mbedtls_cipher_init(&ctx);

    if (!(ci = _get_cipher_info(phdr)))
    {
        /* ATTN-C: unsupported cipher */
        goto done;
    }

    if (mbedtls_cipher_setup(&ctx, ci) != 0)
        goto done;

    const size_t key_bits = phdr->key_bytes * 8;

    if (mbedtls_cipher_setkey(&ctx, key, (int)key_bits, op) != 0)
        goto done;

    if (strcmp(phdr->cipher_mode, LUKS_CIPHER_MODE_CBC_PLAIN) == 0 &&
        mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_NONE) != 0)
    {
        goto done;
    }

    /* Determine the block size */
    if (strcmp(phdr->cipher_mode, LUKS_CIPHER_MODE_ECB) == 0)
    {
        iters = 1;
        block_size = mbedtls_cipher_get_block_size(&ctx);
    }
    else
    {
        block_size = LUKS_SECTOR_SIZE;
    }

    iters = data_size / block_size;

    for (i = 0; i < iters; i++)
    {
        uint64_t pos;
        size_t olen;
        int r;

        if (_gen_iv(phdr, sector + i, iv, key) == -1)
            goto done;

        pos = i * block_size;

        if ((r = mbedtls_cipher_crypt(
                 &ctx,
                 iv,             /* iv */
                 LUKS_IV_SIZE,   /* iv_size */
                 data_in + pos,  /* input */
                 block_size,     /* ilen */
                 data_out + pos, /* output */
                 &olen)) != 0)   /* olen */
        {
            goto done;
        }

        if (olen != block_size)
            goto done;
    }

    ret = 0;

done:
    mbedtls_cipher_free(&ctx);

    return ret;
}

int myst_luks_encrypt(
    const luks_phdr_t* phdr,
    const void* key,
    const uint8_t* data_in,
    uint8_t* data_out,
    size_t data_size,
    uint64_t sector)
{
    const mbedtls_operation_t op = MBEDTLS_ENCRYPT;
    return _crypt(phdr, op, key, data_in, data_out, data_size, sector);
}

int myst_luks_decrypt(
    const luks_phdr_t* phdr,
    const void* key,
    const uint8_t* data_in,
    uint8_t* data_out,
    size_t data_size,
    uint64_t sector)
{
    const mbedtls_operation_t op = MBEDTLS_DECRYPT;
    return _crypt(phdr, op, key, data_in, data_out, data_size, sector);
}
