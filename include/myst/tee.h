// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TEE_H
#define _MYST_TEE_H

#include <stdint.h>

enum
{
    /* Public-facing extended syscalls of Mystikos */
    SYS_myst_max_threads = 1008,
    SYS_myst_gen_creds = 1009,
    SYS_myst_free_creds = 1010,
    SYS_myst_verify_cert = 1011,
    SYS_myst_gen_creds_ex = 1012,
    SYS_myst_free_creds_ex = 1013,

    /* Open Enclave extensions */
    SYS_myst_oe_get_report_v2,
    SYS_myst_oe_free_report,
    SYS_myst_oe_get_target_info_v2,
    SYS_myst_oe_free_target_info,
    SYS_myst_oe_parse_report,
    SYS_myst_oe_verify_report,
    SYS_myst_oe_get_seal_key_by_policy_v2,
    SYS_myst_oe_get_public_key_by_policy,
    SYS_myst_oe_get_public_key,
    SYS_myst_oe_get_private_key_by_policy,
    SYS_myst_oe_get_private_key,
    SYS_myst_oe_free_key,
    SYS_myst_oe_get_seal_key_v2,
    SYS_myst_oe_free_seal_key,
    SYS_myst_oe_generate_attestation_certificate,
    SYS_myst_oe_free_attestation_certificate,
    SYS_myst_oe_verify_attestation_certificate,
    SYS_myst_oe_result_str,
    SYS_myst_oe_get_enclave_start_address,
    SYS_myst_oe_get_enclave_base_address,
};

// Fixed identity property sizes
/**
 * Size of the TEE's unique ID in bytes.
 */
#define MYST_UNIQUE_ID_SIZE 32
/**
 * Size of the TEE's signer ID in bytes.
 */
#define MYST_SIGNER_ID_SIZE 32
/**
 * Size of the TEE's product ID in bytes.
 */
#define MYST_PRODUCT_ID_SIZE 16

/**
 * Self-signed certificate by TEE
 */
#define MYST_CERTIFICATE_PATH "/tmp/myst.crt"
/**
 * Private key corresponding to the self-signed cert
 */
#define MYST_PRIVATE_KEY_PATH "/tmp/myst.key"
/**
 * TEE report attesting to the public key of the cert
 */
#define MYST_ATTESTATION_REPORT_PATH "/tmp/myst.report"

/**
 * The TEE identity for apps running with myst. This should encompass all
 * identity attributes of all kinds of TEEs myst supports.
 */
typedef struct _myst_tee_identity
{
    /** Version of the _myst_tee_identity structure */
    uint32_t id_version;

    /** Security version of the TEE. For SGX enclaves, this is the
     *  ISVN value */
    uint32_t security_version;

    /** Values of the attributes flags for the TEE -
     *  OE_REPORT_ATTRIBUTES_DEBUG: The report is for a debug enclave.
     *  OE_REPORT_ATTRIBUTES_REMOTE: The report can be used for remote
     *  attestation */
    uint64_t attributes;

    /** The unique ID for the TEE.
     * For SGX enclaves, this is the MRENCLAVE value */
    uint8_t unique_id[MYST_UNIQUE_ID_SIZE];

    /** The signer ID for the TEE.
     * For SGX enclaves, this is the MRSIGNER value */
    uint8_t signer_id[MYST_SIGNER_ID_SIZE];

    /** The Product ID for the TEE.
     * For SGX enclaves, this is the ISVPRODID value. */
    uint8_t product_id[MYST_PRODUCT_ID_SIZE];
} myst_tee_identity_t;

#endif /*_MYST_TEE_H */
