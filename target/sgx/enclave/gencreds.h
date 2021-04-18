// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _TLSCREDS_H
#define _TLSCREDS_H

#include <openenclave/enclave.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Generate attestation report from a user-defined claim buffer and optional
 * data, e.g., nonce.
 */
int myst_generate_report_from_claim(
    const uint8_t* claim_buf,
    size_t claim_buf_size,
    uint8_t* optional_data,
    size_t optional_data_size,
    uint8_t** report_buf_out,
    size_t* report_size_out);

/**
 * Generate a x509 self-signed certificate and a separate attestation report
 * from the public key.
 *
 * The caller provided key pair is used to produce the certificate, while
 * the public key is attested by a TEE produced report (in a separate buffer).
 * Since the hash value of the public key and the optional data (could be
 * a nonce) is included in the report, verification of the report proves the
 * validity of the public key (and the optional data).
 */
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
    size_t* report_size_out);

/**
 * Generate a x509 self-signed certificate with OE-extension (embedded quote)
 * and a private key paired with the public key in the certificate.
 */
int myst_gen_creds(
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out);

/**
 * Generate a x509 self-signed certificate without OE-extension (embedded quote)
 * and a private key paired with the public key in the certificate. The quote
 * is returned in a separate buffer report_out.
 */
int myst_gen_creds_ex(
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out,
    uint8_t** report_out,
    size_t* report_size_out);

/**
 * Free the buffers allocated during myst_gen_creds or myst_gen_creds_ex.
 */
void myst_free_creds(
    uint8_t* cert,
    size_t cert_size,
    uint8_t* private_key,
    size_t private_key_size,
    uint8_t* report,
    size_t report_size);

/**
 * Verify the certificate produced by myst_gen_creds.
 */
int myst_verify_cert(
    uint8_t* cert,
    size_t cert_size,
    oe_identity_verify_callback_t verifier,
    void* arg);

#endif /* _TLSCREDS_H */
