// Copyright (c) Open Enclave SDK contributors.
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

    /* Open Enclave extensions */
    SYS_libos_oe_add_vectored_exception_handler = 4096,
    SYS_libos_oe_remove_vectored_exception_handler,
    SYS_libos_oe_is_within_enclave,
    SYS_libos_oe_is_outside_enclave,
    SYS_libos_oe_host_malloc,
    SYS_libos_oe_host_realloc,
    SYS_libos_oe_host_calloc,
    SYS_libos_oe_host_free,
    SYS_libos_oe_strndup,
    SYS_libos_oe_abort,
    SYS_libos_oe_assert_fail,
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
    SYS_libos_oe_get_enclave,
    SYS_libos_oe_random,
    SYS_libos_oe_generate_attestation_certificate,
    SYS_libos_oe_free_attestation_certificate,
    SYS_libos_oe_verify_attestation_certificate,
    SYS_libos_oe_load_module_host_file_system,
    SYS_libos_oe_load_module_host_socket_interface,
    SYS_libos_oe_load_module_host_resolver,
    SYS_libos_oe_load_module_host_epoll,
    SYS_libos_oe_sgx_set_minimum_crl_tcb_issue_date,
    SYS_libos_oe_result_str,
    SYS_libos_oe_get_enclave_status,
    SYS_libos_oe_allocate_ocall_buffer,
    SYS_libos_oe_free_ocall_buffer,
    SYS_libos_oe_call_host_function,
};

#endif /* _LIBOS_SYSCALLEXT_H */
