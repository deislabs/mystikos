#ifndef _LIBOS_TEE_H
#define _LIBOS_TEE_H


// Fixed identity property sizes
/**
 * Size of the TEE's unique ID in bytes.
 */
#define LIBOS_UNIQUE_ID_SIZE 32
/**
 * Size of the TEE's signer ID in bytes.
 */
#define LIBOS_SIGNER_ID_SIZE 32
/**
 * Size of the TEE's product ID in bytes.
 */
#define LIBOS_PRODUCT_ID_SIZE 16

/**
 * The TEE identity for apps running with libos. This should encompass all
 * identity attributes of all kinds of TEEs libos supports.
 */
typedef struct _libos_tee_identity
{
    /** Version of the _libos_tee_identity structure */
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
    uint8_t unique_id[LIBOS_UNIQUE_ID_SIZE];

    /** The signer ID for the TEE.
     * For SGX enclaves, this is the MRSIGNER value */
    uint8_t signer_id[LIBOS_SIGNER_ID_SIZE];

    /** The Product ID for the TEE.
     * For SGX enclaves, this is the ISVPRODID value. */
    uint8_t product_id[LIBOS_PRODUCT_ID_SIZE];
} libos_tee_identity_t;

#endif /*_LIBOS_TEE_H */