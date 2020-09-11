#include <libos/syscallext.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

oe_result_t oe_random(void* data, size_t size)
{
    return (oe_result_t)syscall(SYS_libos_oe_random, data, size);
}

oe_result_t oe_generate_attestation_certificate(
    const unsigned char* subject_name,
    uint8_t* private_key,
    size_t private_key_size,
    uint8_t* public_key,
    size_t public_key_size,
    uint8_t** output_cert,
    size_t* output_cert_size)
{
    long args[] = {
        (long)subject_name,
        (long)private_key,
        (long)private_key_size,
        (long)public_key,
        (long)public_key_size,
        (long)output_cert,
        (long)output_cert_size,
    };

    return (oe_result_t)syscall(
        SYS_libos_oe_generate_attestation_certificate, args);
}

oe_result_t oe_get_public_key_by_policy(
    oe_seal_policy_t seal_policy,
    const oe_asymmetric_key_params_t* key_params,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    return (oe_result_t)syscall(
        SYS_libos_oe_get_public_key_by_policy,
        seal_policy,
        key_params,
        key_buffer,
        key_buffer_size,
        key_info,
        key_info_size);
}

oe_result_t oe_get_private_key_by_policy(
    oe_seal_policy_t seal_policy,
    const oe_asymmetric_key_params_t* key_params,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    return (oe_result_t)syscall(
        SYS_libos_oe_get_private_key_by_policy,
        seal_policy,
        key_params,
        key_buffer,
        key_buffer_size,
        key_info,
        key_info_size);
}

void oe_free_key(
    uint8_t* key_buffer,
    size_t key_buffer_size,
    uint8_t* key_info,
    size_t key_info_size)
{
    syscall(
        SYS_libos_oe_free_key,
        key_buffer,
        key_buffer_size,
        key_info,
        key_info_size);
}

void oe_free_attestation_certificate(uint8_t* cert)
{
    syscall(SYS_libos_oe_free_attestation_certificate, cert);
}

oe_result_t oe_verify_attestation_certificate(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_identity_verify_callback_t enclave_identity_callback,
    void* arg)
{
    syscall(
        SYS_libos_oe_verify_attestation_certificate,
        cert_in_der,
        cert_in_der_len,
        enclave_identity_callback,
        arg);
}

bool oe_is_within_enclave(const void* ptr, size_t size)
{
    return (bool)syscall(SYS_libos_oe_is_within_enclave, ptr, size);
}

bool oe_is_outside_enclave(const void* ptr, size_t size)
{
    return (bool)syscall(SYS_libos_oe_is_outside_enclave, ptr, size);
}

oe_result_t oe_get_enclave_status()
{
    return (oe_result_t)syscall(SYS_libos_oe_get_enclave_status);
}

size_t oe_strlen(const char* s)
{
    return strlen(s);
}

void* oe_allocate_ocall_buffer(size_t size)
{
    return (void*)syscall(SYS_libos_oe_allocate_ocall_buffer, size);
}

void oe_free_ocall_buffer(void* buffer)
{
    syscall(SYS_libos_oe_free_ocall_buffer, buffer);
}

oe_result_t oe_call_host_function(
    size_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    oe_result_t result = (oe_result_t)syscall(
        SYS_libos_oe_call_host_function,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);

    return result;
}
