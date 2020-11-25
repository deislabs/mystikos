// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_SYSCALLEXT_H
#define _LIBOS_SYSCALLEXT_H

#include <libos/types.h>
#include <sys/types.h>

/* libos-specific syscalls */
enum
{
    SYS_libos_trace = 1001,
    SYS_libos_trace_ptr = 1002,
    SYS_libos_dump_stack = 1003,
    SYS_libos_dump_ehdr = 1004,
    SYS_libos_dump_argv = 1005,
    SYS_libos_add_symbol_file = 1006,
    SYS_libos_load_symbols = 1007,
    SYS_libos_unload_symbols = 1008,
    SYS_libos_gen_creds = 1009,
    SYS_libos_free_creds = 1010,
    SYS_libos_verify_cert = 1011,
    SYS_libos_clone = 1012,
    SYS_libos_gcov_init = 1013,
    SYS_libos_max_threads = 1014,
    SYS_libos_poll_wake = 1015,

    /* Open Enclave extensions */
    SYS_libos_oe_get_report_v2,
    SYS_libos_oe_free_report,
    SYS_libos_oe_get_target_info_v2,
    SYS_libos_oe_free_target_info,
    SYS_libos_oe_parse_report,
    SYS_libos_oe_verify_report,
    SYS_libos_oe_get_seal_key_by_policy_v2,
    SYS_libos_oe_get_public_key_by_policy,
    SYS_libos_oe_get_public_key,
    SYS_libos_oe_get_private_key_by_policy,
    SYS_libos_oe_get_private_key,
    SYS_libos_oe_free_key,
    SYS_libos_oe_get_seal_key_v2,
    SYS_libos_oe_free_seal_key,
    SYS_libos_oe_generate_attestation_certificate,
    SYS_libos_oe_free_attestation_certificate,
    SYS_libos_oe_verify_attestation_certificate,
    SYS_libos_oe_result_str,
};

#endif /* _LIBOS_SYSCALLEXT_H */
