// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/x509_crt.h>
#include <myst/crypto.h>
#include <myst/eraise.h>
#include <myst/sha256.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ISSUER "MYSTIKOS"
#define DATE_NOT_VALID_BEFORE "20210101000000"
#define DATE_NOT_VALID_AFTER "20501231235959"

static mbedtls_ctr_drbg_context _drbg;
static mbedtls_entropy_context _entropy;
static int initialized = 0;

static mbedtls_ctr_drbg_context* _get_ctr_drbg()
{
    if (!initialized)
    {
        // ATTN: possible to initialize twice. Make this thread safe.
        mbedtls_ctr_drbg_init(&_drbg);
        mbedtls_entropy_init(&_entropy);
        assert(
            mbedtls_ctr_drbg_seed(
                &_drbg, mbedtls_entropy_func, &_entropy, NULL, 0) >= 0);
        initialized = 1;
    }
    return &_drbg;
}

static int _mbedtls_generate_key_pair(
    mbedtls_pk_type_t key_type,
    uint8_t** public_key_out,
    size_t* public_key_size,
    uint8_t** private_key_out,
    size_t* private_key_size)
{
    int ret = 0;
    const size_t bufsize = 4096;
    unsigned char buffer1[bufsize];
    unsigned char buffer2[bufsize];
    size_t len1 = 0;
    size_t len2 = 0;

    // Only support RSA or EC key now.
    assert(key_type == MBEDTLS_PK_RSA || key_type == MBEDTLS_PK_ECKEY);
    assert(public_key_out && private_key_out);

    *public_key_out = *private_key_out = 0;

    mbedtls_pk_context pk_context;
    mbedtls_pk_init(&pk_context);

    mbedtls_ctr_drbg_context* ctr_drbg = _get_ctr_drbg();

    // Initialize context based on key type.
    ECHECK(mbedtls_pk_setup(&pk_context, mbedtls_pk_info_from_type(key_type)));

    if (key_type == MBEDTLS_PK_RSA)
    {
        // Generate an ephemeral RSA key pair with exponent 65537.
        ECHECK(mbedtls_rsa_gen_key(
            mbedtls_pk_rsa(pk_context),
            mbedtls_ctr_drbg_random,
            ctr_drbg,
            2048,
            65537));
    }
    else if (key_type == MBEDTLS_PK_ECKEY)
    {
        // Generate an ephemeral EC key pair with secp256r1 curve.
        ECHECK(mbedtls_ecp_gen_key(
            MBEDTLS_ECP_DP_SECP256R1,
            mbedtls_pk_ec(pk_context),
            mbedtls_ctr_drbg_random,
            ctr_drbg));
    }

    // Write out the public/private key in PEM format
    ECHECK(mbedtls_pk_write_pubkey_pem(&pk_context, buffer1, bufsize));
    ECHECK(mbedtls_pk_write_key_pem(&pk_context, buffer2, bufsize));

    len1 = strlen((const char*)buffer1) + 1;
    len2 = strlen((const char*)buffer2) + 1;

    if ((*public_key_out = calloc(len1, 1)) == NULL)
        ERAISE(-ENOMEM);

    if ((*private_key_out = calloc(len2, 1)) == NULL)
        ERAISE(-ENOMEM);

    strcpy((char*)*public_key_out, (const char*)buffer1);
    *public_key_size = len1;
    strcpy((char*)*private_key_out, (const char*)buffer2);
    *private_key_size = len2;

done:
    mbedtls_pk_free(&pk_context);
    if (ret)
    {
        free(*private_key_out);
        free(*public_key_out);
        *public_key_out = *private_key_out = NULL;
        *public_key_size = *private_key_size = 0;
    }
    return ret;
}

int _mbedtls_generate_x509_certificate_with_extension(
    const char* subject_name,
    uint8_t* public_key,
    size_t public_key_size,
    uint8_t* private_key,
    size_t private_key_size,
    const char* issuer,
    const char* nbf,
    const char* exp,
    myst_cert_extension_config_t* config,
    uint8_t** cert_buf_out,
    size_t* cert_size_out)
{
    mbedtls_mpi serial;
    mbedtls_x509write_cert x509cert = {0};
    mbedtls_pk_context subject_key;
    mbedtls_pk_context issuer_key;
    mbedtls_ctr_drbg_context* ctr_drbg = NULL;
    int ret = 0;

    mbedtls_pk_init(&subject_key);
    mbedtls_pk_init(&issuer_key);
    mbedtls_mpi_init(&serial);
    mbedtls_x509write_crt_init(&x509cert);
    mbedtls_x509write_crt_set_md_alg(&x509cert, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&x509cert, &subject_key);
    mbedtls_x509write_crt_set_issuer_key(&x509cert, &issuer_key);

    ctr_drbg = _get_ctr_drbg();

    // create pk_context for both public and private keys
    ECHECK(mbedtls_pk_parse_public_key(
        &subject_key, (const unsigned char*)public_key, public_key_size));

    ECHECK(mbedtls_pk_parse_key(
        &issuer_key,
        (const unsigned char*)private_key,
        private_key_size,
        NULL,
        0));

    ECHECK(mbedtls_x509write_crt_set_subject_name(&x509cert, subject_name));

    ECHECK(mbedtls_x509write_crt_set_issuer_name(&x509cert, issuer));

    ECHECK(mbedtls_mpi_read_string(&serial, 10, "1"));

    ECHECK(mbedtls_x509write_crt_set_serial(&x509cert, &serial));

    ECHECK(mbedtls_x509write_crt_set_validity(&x509cert, nbf, exp));

    // Mark the issuer as non-CA
    ECHECK(mbedtls_x509write_crt_set_basic_constraints(&x509cert, 0, -1));

    // Embed custom data as extensions in the cert
    if (config)
    {
        // Set the subjectKeyIdentifier extension for a CRT Requires that
        // mbedtls_x509write_crt_set_subject_key() has been called before
        ECHECK(mbedtls_x509write_crt_set_subject_key_identifier(&x509cert));

        // Set the authorityKeyIdentifier extension for a CRT Requires that
        // mbedtls_x509write_crt_set_issuer_key() has been called before.
        ECHECK(mbedtls_x509write_crt_set_authority_key_identifier(&x509cert));

        ECHECK(mbedtls_x509write_crt_set_extension(
            &x509cert,
            (char*)config->ext_oid,
            config->ext_oid_size,
            0,
            (const uint8_t*)config->ext_data_buf,
            config->ext_data_buf_size));
    }

    // Write a built up certificate to a X509 DER structure Note: data
    // is written at the end of the buffer! Use the return value to
    // determine where you should start using the buffer.
    {
        unsigned char* buf = NULL;
        int actual_len = 0;
        const size_t tmp_size = 16000;
        unsigned char tmp[tmp_size];
        ECHECK(
            actual_len = mbedtls_x509write_crt_der(
                &x509cert, tmp, tmp_size, mbedtls_ctr_drbg_random, ctr_drbg));

        if ((buf = malloc((size_t)actual_len)) == NULL)
            ERAISE(-ENOMEM);

        memmove(buf, tmp + tmp_size - actual_len, (size_t)actual_len);

        *cert_size_out = (size_t)actual_len;
        *cert_buf_out = buf;
    }

done:
    mbedtls_mpi_free(&serial);
    mbedtls_x509write_crt_free(&x509cert);
    mbedtls_pk_free(&issuer_key);
    mbedtls_pk_free(&subject_key);

    return ret;
}

int myst_generate_x509_self_signed_cert(
    uint8_t* public_key,
    size_t public_key_size,
    uint8_t* private_key,
    size_t private_key_size,
    myst_cert_extension_config_t* config,
    uint8_t** cert_buf_out,
    size_t* cert_size_out)
{
    return _mbedtls_generate_x509_certificate_with_extension(
        MYST_CERT_COMMON_NAME,
        public_key,
        public_key_size,
        private_key,
        private_key_size,
        ISSUER,
        DATE_NOT_VALID_BEFORE,
        DATE_NOT_VALID_AFTER,
        config,
        cert_buf_out,
        cert_size_out);
}

int myst_generate_rsa_key_pair(
    uint8_t** public_key_out,
    size_t* public_key_size,
    uint8_t** private_key_out,
    size_t* private_key_size)
{
    return _mbedtls_generate_key_pair(
        MBEDTLS_PK_RSA,
        public_key_out,
        public_key_size,
        private_key_out,
        private_key_size);
}

int myst_generate_ec_key_pair(
    uint8_t** public_key_out,
    size_t* public_key_size,
    uint8_t** private_key_out,
    size_t* private_key_size)
{
    return _mbedtls_generate_key_pair(
        MBEDTLS_PK_ECKEY,
        public_key_out,
        public_key_size,
        private_key_out,
        private_key_size);
}
