// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static oe_result_t _generate_key_pair(
    uint8_t** public_key_out,
    size_t* public_key_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out)
{
    oe_result_t result = OE_FAILURE;
    oe_result_t ret;
    oe_asymmetric_key_params_t params;
    char user_data[] = "__USER_DATA__";
    size_t user_data_size = sizeof(user_data) - 1;
    uint8_t* public_key = NULL;
    size_t public_key_size = 0;
    uint8_t* private_key = NULL;
    size_t private_key_size = 0;

    *public_key_out = NULL;
    *public_key_size_out = 0;
    *private_key_out = NULL;
    *private_key_size_out = 0;

    memset(&params, 0, sizeof(params));
    params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1;
    params.format = OE_ASYMMETRIC_KEY_PEM;
    params.user_data = user_data;
    params.user_data_size = user_data_size;

    if ((ret = oe_get_public_key_by_policy(
             OE_SEAL_POLICY_UNIQUE,
             &params,
             &public_key,
             &public_key_size,
             NULL,
             NULL)) != OE_OK)
    {
        result = ret;
        goto done;
    }

    if ((ret = oe_get_private_key_by_policy(
             OE_SEAL_POLICY_UNIQUE,
             &params,
             &private_key,
             &private_key_size,
             NULL,
             NULL)) != OE_OK)
    {
        result = ret;
        goto done;
    }

    *private_key_out = private_key;
    *private_key_size_out = private_key_size;
    private_key = NULL;

    *public_key_out = public_key;
    *public_key_size_out = public_key_size;
    public_key = NULL;

    result = OE_OK;

done:

    if (private_key)
        oe_free_key(private_key, private_key_size, NULL, 0);

    if (public_key)
        oe_free_key(public_key, public_key_size, NULL, 0);

    return result;
}

static oe_result_t _generate_cert_and_private_key(
    const char* common_name,
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out)
{
    oe_result_t result = OE_FAILURE;
    oe_result_t ret;
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

    if ((ret = _generate_key_pair(
             &public_key, &public_key_size, &private_key, &private_key_size)) !=
        OE_OK)
    {
        result = ret;
        goto done;
    }

    if ((ret = oe_generate_attestation_certificate(
             (unsigned char*)common_name,
             private_key,
             private_key_size,
             public_key,
             public_key_size,
             &cert,
             &cert_size)) != OE_OK)
    {
        result = ret;
        goto done;
    }

    *private_key_out = private_key;
    *private_key_size_out = private_key_size;
    private_key = NULL;

    *cert_out = cert;
    *cert_size_out = cert_size;
    cert = NULL;

    result = OE_OK;

done:

    if (private_key)
        oe_free_key(private_key, private_key_size, NULL, 0);

    if (public_key)
        oe_free_key(public_key, public_key_size, NULL, 0);

    if (cert)
        oe_free_attestation_certificate(cert);

    return result;
}

static int test_gen_creds(
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out)
{
    int ret = -1;
    uint8_t* cert = NULL;
    size_t cert_size;
    uint8_t* private_key = NULL;
    size_t private_key_size;
    const char* common_name = "CN=Open Enclave SDK,O=OESDK TLS,C=US";

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

    if (cert)
        oe_free_key(cert, cert_size, NULL, 0);

    if (private_key)
        oe_free_key(private_key, private_key_size, NULL, 0);

    if (cert)
        oe_free_attestation_certificate(cert);

    return ret;
}

static void _free_creds(
    uint8_t* cert,
    size_t cert_size,
    uint8_t* private_key,
    size_t private_key_size)
{
    if (cert)
        oe_free_key(cert, cert_size, NULL, 0);

    if (private_key)
        oe_free_key(private_key, private_key_size, NULL, 0);
}

static oe_result_t _verifier(oe_identity_t* identity, void* arg)
{
    const uint64_t OE_ISVSVN = 1;
    const uint8_t OE_ISVPRODID[OE_PRODUCT_ID_SIZE] = {1};

    // OE SDK Debug MRSIGNER
    const uint8_t OE_MRSIGNER[] = {
        0xca, 0x9a, 0xd7, 0x33, 0x14, 0x48, 0x98, 0x0a, 0xa2, 0x88, 0x90,
        0xce, 0x73, 0xe4, 0x33, 0x63, 0x83, 0x77, 0xf1, 0x79, 0xab, 0x44,
        0x56, 0xb2, 0xfe, 0x23, 0x71, 0x93, 0x19, 0x3a, 0x8d, 0x0a};

    (void)arg;

    const uint8_t* mrenclave = identity->unique_id;
    const uint8_t* mrsigner = identity->signer_id;
    const uint8_t* isvprodid = identity->product_id;
    uint64_t isvsvn = identity->security_version;

    if (!mrenclave || !mrsigner || !isvprodid)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    printf("=== _verify_identity()\n");
    printf("ISVSVN: %lu\n", isvsvn);

    if (memcmp(mrsigner, OE_MRSIGNER, OE_SIGNER_ID_SIZE) == 0)
    {
        if (memcmp(isvprodid, OE_ISVPRODID, OE_PRODUCT_ID_SIZE) != 0)
        {
            fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
            return OE_VERIFY_FAILED;
        }
        if (isvsvn != OE_ISVSVN)
        {
            fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
            return OE_VERIFY_FAILED;
        }
    }
    else
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    return OE_OK;
}

int test_verify_cert(
    uint8_t* cert,
    size_t cert_size,
    oe_identity_verify_callback_t verifier,
    void* arg)
{
    return oe_verify_attestation_certificate(cert, cert_size, verifier, arg);
}

int main(int argc, const char* argv[])
{
    uint8_t* cert = NULL;
    size_t cert_size;
    uint8_t* private_key = NULL;
    size_t private_key_size;

    if (strcmp(getenv("MYST_TARGET"), "sgx") == 0)
    {
        assert(
            test_gen_creds(
                &cert, &cert_size, &private_key, &private_key_size) == 0);

        assert(test_verify_cert(cert, cert_size, _verifier, NULL) == 0);

        printf("cert_size: %zu\n", cert_size);
        printf("private_key_size: %zu\n", private_key_size);

        _free_creds(cert, cert_size, private_key, private_key_size);
    }

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
