// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "gencreds.h"
#include <assert.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <myst/crypto.h>
#include <myst/eraise.h>
#include <myst/sha256.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <string.h>

static void _clean_free(uint8_t* buf, size_t len)
{
    oe_free_key(buf, len, NULL, 0);
}

static int _generate_cert_and_private_key(
    const char* common_name,
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out)
{
    int ret = 0;
    uint8_t* cert = NULL;
    size_t cert_size;
    uint8_t* private_key = NULL;
    size_t private_key_size;
    uint8_t* public_key = NULL;
    size_t public_key_size;

    *cert_out = NULL;
    *cert_size_out = 0;
    *private_key_out = NULL;
    *private_key_size_out = 0;

    ECHECK(myst_generate_ec_key_pair(
        &public_key,
        &public_key_size,
        &private_key,
        &private_key_size,
        MYST_PEM));

    if ((ret = oe_generate_attestation_certificate(
             (unsigned char*)common_name,
             private_key,
             private_key_size,
             public_key,
             public_key_size,
             &cert,
             &cert_size)) != OE_OK)
    {
        ERAISE(-ret);
    }

    *cert_out = cert;
    *cert_size_out = cert_size;
    cert = NULL;

    *private_key_out = private_key;
    *private_key_size_out = private_key_size;
    private_key = NULL; /* Set to NULL so private_key_out won't be freed */

done:

    _clean_free(private_key, private_key_size);
    _clean_free(public_key, public_key_size);
    free(cert);

    return ret;
}

int myst_gen_creds(
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out)
{
    int ret = 0;
    uint8_t* cert = NULL;
    size_t cert_size;
    uint8_t* private_key = NULL;
    size_t private_key_size;
    const char* common_name = MYST_CERT_COMMON_NAME;

    if (cert_out)
        *cert_out = NULL;

    if (cert_size_out)
        *cert_size_out = 0;

    if (private_key_out)
        *private_key_out = NULL;

    if (private_key_size_out)
        *private_key_size_out = 0;

    if (!cert_out || !cert_size_out || !private_key_out ||
        !private_key_size_out)
    {
        printf("TRACE:%d\n", __LINE__);
        goto done;
    }

    /* Generate the attested certificate and private key */
    if (_generate_cert_and_private_key(
            common_name, &cert, &cert_size, &private_key, &private_key_size) !=
        OE_OK)
    {
        printf("TRACE:%d\n", __LINE__);
        goto done;
    }

    *cert_out = cert;
    cert = NULL;
    *cert_size_out = cert_size;
    *private_key_out = private_key;
    private_key = NULL;
    *private_key_size_out = private_key_size;

    ret = 0;

done:

    free(cert);
    _clean_free(private_key, private_key_size);

    return ret;
}

int myst_gen_creds_ex(
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out,
    uint8_t** report_out,
    size_t* report_size_out)
{
    int ret = 0;
    uint8_t* private_key = NULL;
    size_t private_key_size;
    uint8_t* public_key = NULL;
    size_t public_key_size;
    size_t buflen = 4096;
    uint8_t derbuf[4096];

    *cert_out = NULL;
    *cert_size_out = 0;
    *private_key_out = NULL;
    *private_key_size_out = 0;
    *report_out = NULL;
    *report_size_out = 0;

    ECHECK(myst_generate_rsa_key_pair(
        &public_key,
        &public_key_size,
        &private_key,
        &private_key_size,
        MYST_PEM));

    ECHECK(myst_generate_x509_self_signed_cert(
        public_key,
        public_key_size,
        private_key,
        private_key_size,
        NULL,
        cert_out,
        cert_size_out,
        MYST_DER));

    // Convert public key from PEM to DER
    ECHECK(myst_pem_to_der(public_key, public_key_size, derbuf, &buflen));
    assert(buflen < 4096);

#if DEBUG
    fprintf(stderr, "==== Public key (%ld): ", buflen);
    for (size_t i = 0; i < buflen; i++)
    {
        fprintf(stderr, "%02x", derbuf[i]);
    }
    fprintf(stderr, "\n");
#endif

    ECHECK(myst_generate_report_from_claim(
        derbuf, buflen, NULL, 0, report_out, report_size_out));

    *private_key_out = private_key;
    *private_key_size_out = private_key_size;
    private_key = NULL;

done:

    _clean_free(public_key, public_key_size);

    if (ret)
    {
        _clean_free(private_key, private_key_size);
        free(*cert_out);
        free(*report_out);
    }
    return ret;
}

int myst_generate_report_from_claim(
    const uint8_t* claim_buf,
    size_t claim_buf_size,
    uint8_t* optional_data,
    size_t optional_data_size,
    uint8_t** report_buf_out,
    size_t* report_size_out)
{
    int ret = 0;
    int r = 0;
    myst_sha256_t sha256 = {0};
    uint8_t* tmpbuf = NULL;
    size_t tmpbuf_size = 0;

    ECHECK(myst_sha256(&sha256, claim_buf, claim_buf_size));

#if DEBUG
    fprintf(stderr, "==== Report Claim (%ld): ", claim_buf_size);
    for (size_t i = 0; i < claim_buf_size; i++)
    {
        fprintf(stderr, "%02x", claim_buf[i]);
    }
    fprintf(stderr, "\n==== Report data (%d): ", MYST_SHA256_SIZE);
    for (size_t i = 0; i < MYST_SHA256_SIZE; i++)
    {
        fprintf(stderr, "%02x", sha256.data[i]);
    }
    fprintf(stderr, "\n");
#endif

    if ((r = oe_get_report(
             OE_REPORT_FLAGS_REMOTE_ATTESTATION,
             (const uint8_t*)&sha256,
             MYST_SHA256_SIZE,
             optional_data,
             optional_data_size,
             &tmpbuf,
             &tmpbuf_size)) != OE_OK)
        ERAISE(-r);

    *report_buf_out = tmpbuf;
    *report_size_out = tmpbuf_size;
    tmpbuf = NULL;

done:

    free(tmpbuf);

    return ret;
}

int myst_generate_certificate_and_report(
    uint8_t* private_key,
    size_t private_key_size,
    uint8_t* public_key,
    size_t public_key_size,
    uint8_t* optional_data,
    size_t optional_data_size,
    uint8_t** cert_buf_out,
    size_t* cert_size_out,
    uint8_t** report_buf_out,
    size_t* report_size_out)
{
    int ret = 0;
    *report_buf_out = *cert_buf_out = NULL;

    /* Generate the certificate */
    ECHECK(myst_generate_x509_self_signed_cert(
        public_key,
        public_key_size,
        private_key,
        private_key_size,
        NULL,
        cert_buf_out,
        cert_size_out,
        MYST_DER));

    ECHECK(myst_generate_report_from_claim(
        public_key,
        public_key_size,
        optional_data,
        optional_data_size,
        report_buf_out,
        report_size_out));

done:

    if (ret)
    {
        /* Clean up on failure */
        free(*cert_buf_out);
        free(*report_buf_out);
        *report_buf_out = *cert_buf_out = NULL;
        *report_size_out = *cert_size_out = 0;
    }
    return ret;
}

void myst_free_creds(
    uint8_t* cert,
    size_t cert_size,
    uint8_t* private_key,
    size_t private_key_size,
    uint8_t* report,
    size_t report_size)
{
    _clean_free(cert, cert_size);
    _clean_free(private_key, private_key_size);
    _clean_free(report, report_size);
}

int myst_verify_cert(
    uint8_t* cert,
    size_t cert_size,
    oe_identity_verify_callback_t verifier,
    void* arg)
{
    return oe_verify_attestation_certificate(cert, cert_size, verifier, arg);
}
