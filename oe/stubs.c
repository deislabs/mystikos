// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/syscallext.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

oe_result_t oe_get_report_v2(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    uint64_t args[] = {
        (uint64_t)flags,
        (uint64_t)report_data,
        (uint64_t)report_data_size,
        (uint64_t)opt_params,
        (uint64_t)opt_params_size,
        (uint64_t)report_buffer,
        (uint64_t)report_buffer_size,
    };

    return (oe_result_t)syscall(SYS_myst_oe_get_report_v2, args);
}

void oe_free_report(uint8_t* report_buffer)
{
    uint64_t args[] = {(uint64_t)report_buffer};
    syscall(SYS_myst_oe_free_report, args);
}

oe_result_t oe_get_target_info_v2(
    const uint8_t* report,
    size_t report_size,
    void** target_info_buffer,
    size_t* target_info_size)
{
    uint64_t args[] = {
        (uint64_t)report,
        (uint64_t)report_size,
        (uint64_t)target_info_buffer,
        (uint64_t)target_info_size,
    };
    return (oe_result_t)syscall(SYS_myst_oe_get_target_info_v2, args);
}

void oe_free_target_info(void* target_info)
{
    uint64_t args[] = {(uint64_t)target_info};
    syscall(SYS_myst_oe_free_target_info, args);
}

oe_result_t oe_parse_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    uint64_t args[] = {
        (uint64_t)report,
        (uint64_t)report_size,
        (uint64_t)parsed_report,
    };
    return (oe_result_t)syscall(SYS_myst_oe_parse_report, args);
}

oe_result_t oe_verify_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    uint64_t args[] = {
        (uint64_t)report,
        (uint64_t)report_size,
        (uint64_t)parsed_report,
    };
    return (oe_result_t)syscall(SYS_myst_oe_verify_report, args);
}

oe_result_t oe_get_seal_key_by_policy_v2(
    oe_seal_policy_t seal_policy,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    uint64_t args[] = {
        (uint64_t)seal_policy,
        (uint64_t)key_buffer,
        (uint64_t)key_buffer_size,
        (uint64_t)key_info,
        (uint64_t)key_info_size,
    };
    return (oe_result_t)syscall(SYS_myst_oe_get_seal_key_by_policy_v2, args);
}

oe_result_t oe_get_public_key_by_policy(
    oe_seal_policy_t seal_policy,
    const oe_asymmetric_key_params_t* key_params,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    uint64_t args[] = {
        (uint64_t)seal_policy,
        (uint64_t)key_params,
        (uint64_t)key_buffer,
        (uint64_t)key_buffer_size,
        (uint64_t)key_info,
        (uint64_t)key_info_size,
    };
    return (oe_result_t)syscall(SYS_myst_oe_get_public_key_by_policy, args);
}

oe_result_t oe_get_public_key(
    const oe_asymmetric_key_params_t* key_params,
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    uint64_t args[] = {
        (uint64_t)key_params,
        (uint64_t)key_info,
        (uint64_t)key_info_size,
        (uint64_t)key_buffer,
        (uint64_t)key_buffer_size,
    };
    return (oe_result_t)syscall(SYS_myst_oe_get_public_key, args);
}

oe_result_t oe_get_private_key_by_policy(
    oe_seal_policy_t seal_policy,
    const oe_asymmetric_key_params_t* key_params,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    uint64_t args[] = {
        (uint64_t)seal_policy,
        (uint64_t)key_params,
        (uint64_t)key_buffer,
        (uint64_t)key_buffer_size,
        (uint64_t)key_info,
        (uint64_t)key_info_size,
    };
    return (oe_result_t)syscall(SYS_myst_oe_get_private_key_by_policy, args);
}

oe_result_t oe_get_private_key(
    const oe_asymmetric_key_params_t* key_params,
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    uint64_t args[] = {
        (uint64_t)key_params,
        (uint64_t)key_info,
        (uint64_t)key_info_size,
        (uint64_t)key_buffer,
        (uint64_t)key_buffer_size,
    };
    return (oe_result_t)syscall(SYS_myst_oe_get_private_key, args);
}

void oe_free_key(
    uint8_t* key_buffer,
    size_t key_buffer_size,
    uint8_t* key_info,
    size_t key_info_size)
{
    uint64_t args[] = {
        (uint64_t)key_buffer,
        (uint64_t)key_buffer_size,
        (uint64_t)key_info,
        (uint64_t)key_info_size,
    };
    syscall(SYS_myst_oe_free_key, args);
}

oe_result_t oe_get_seal_key_v2(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    uint64_t args[] = {
        (uint64_t)key_info,
        (uint64_t)key_info_size,
        (uint64_t)key_buffer,
        (uint64_t)key_buffer_size,
    };
    return (oe_result_t)syscall(SYS_myst_oe_get_seal_key_v2, args);
}

void oe_free_seal_key(uint8_t* key_buffer, uint8_t* key_info)
{
    uint64_t args[] = {
        (uint64_t)key_buffer,
        (uint64_t)key_info,
    };
    syscall(SYS_myst_oe_free_seal_key, args);
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
    uint64_t args[] = {
        (uint64_t)subject_name,
        (uint64_t)private_key,
        (uint64_t)private_key_size,
        (uint64_t)public_key,
        (uint64_t)public_key_size,
        (uint64_t)output_cert,
        (uint64_t)output_cert_size,
    };

    return (oe_result_t)syscall(
        SYS_myst_oe_generate_attestation_certificate, args);
}

void oe_free_attestation_certificate(uint8_t* cert)
{
    uint64_t args[] = {
        (uint64_t)cert,
    };

    syscall(SYS_myst_oe_free_attestation_certificate, args);
}

oe_result_t oe_verify_attestation_certificate(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_identity_verify_callback_t enclave_identity_callback,
    void* arg)
{
    uint64_t args[] = {
        (uint64_t)cert_in_der,
        (uint64_t)cert_in_der_len,
        (uint64_t)enclave_identity_callback,
        (uint64_t)arg,
    };

    return (oe_result_t)syscall(
        SYS_myst_oe_verify_attestation_certificate, args);
}

const char* oe_result_string(oe_result_t result)
{
    uint64_t args[] = {
        (uint64_t)result,
    };

    return (const char*)syscall(SYS_myst_oe_result_str, args);
}
