#ifndef _MYST_OEPRIVATE_RSA_H
#define _MYST_OEPRIVATE_RSA_H

#include <stdint.h>

typedef enum _oe_result oe_result_t;

typedef enum _oe_hash_type
{
    OE_HASH_TYPE_SHA256,
    OE_HASH_TYPE_SHA512,
} oe_hash_type_t;

typedef struct _oe_rsa_private_key
{
    uint64_t impl[4];
} oe_rsa_private_key_t;

typedef struct _oe_rsa_public_key
{
    uint64_t impl[4];
} oe_rsa_public_key_t;

oe_result_t oe_rsa_private_key_read_pem(
    oe_rsa_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_size);

oe_result_t oe_rsa_public_key_read_pem(
    oe_rsa_public_key_t* public_key,
    const uint8_t* pem_data,
    size_t pem_size);

oe_result_t oe_rsa_private_key_free(oe_rsa_private_key_t* private_key);

oe_result_t oe_rsa_public_key_free(oe_rsa_public_key_t* public_key);

oe_result_t oe_rsa_private_key_sign(
    const oe_rsa_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size);

oe_result_t oe_rsa_public_key_verify(
    const oe_rsa_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size);

oe_result_t oe_rsa_public_key_get_modulus(
    const oe_rsa_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size);;

#endif /* _MYST_OEPRIVATE_RSA_H */
