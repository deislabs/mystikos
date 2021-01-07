// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TEE_H
#define _MYST_TEE_H

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