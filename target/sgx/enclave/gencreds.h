// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _TLSCREDS_H
#define _TLSCREDS_H

#include <openenclave/enclave.h>
#include <stddef.h>
#include <stdint.h>

int myst_gen_creds(
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out);

void myst_free_creds(
    uint8_t* cert,
    size_t cert_size,
    uint8_t* private_key,
    size_t private_key_size);

int myst_verify_cert(
    uint8_t* cert,
    size_t cert_size,
    oe_identity_verify_callback_t verifier,
    void* arg);

#endif /* _TLSCREDS_H */
