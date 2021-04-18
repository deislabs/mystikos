// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_CRYPTO_H
#define _MYST_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define MYST_CERT_COMMON_NAME "CN=MYST-TLS-CERT,O=MYSTIKOS,C=US"

typedef struct myst_cert_extension_config
{
    uint8_t* ext_oid;
    size_t ext_oid_size;
    uint8_t* ext_data_buf;
    size_t ext_data_buf_size;
} myst_cert_extension_config_t;

/**
 * Generate a RSA public-private key pair.
 *
 * The keys are stored into the buffers in PEM format.
 * The caller is responsible for freeing the buffer.
 */
int myst_generate_rsa_key_pair(
    uint8_t** public_key_out,
    size_t* public_key_size,
    uint8_t** private_key_out,
    size_t* private_key_size);

/**
 * Generate an EC public-private key pair.
 *
 * The keys are stored into the buffers in PEM format.
 * The caller is responsible for freeing the buffer.
 */
int myst_generate_ec_key_pair(
    uint8_t** public_key_out,
    size_t* public_key_size,
    uint8_t** private_key_out,
    size_t* private_key_size);

/**
 * Generate a x509 self signed certificate with possible extension.
 *
 * The keys are pre-generated and could be either RSA or EC keys.
 * No extension is included if extension_config is null.
 * The certificate is stored into the buffer in DER format.
 * The caller is responsible for freeing the buffer.
 */
int myst_generate_x509_self_signed_cert(
    uint8_t* public_key,
    size_t public_key_size,
    uint8_t* private_key,
    size_t private_key_size,
    myst_cert_extension_config_t* extension_config,
    uint8_t** cert_buf_out,
    size_t* cert_size_out);

#endif /* _MYST_CRYPTO_H */