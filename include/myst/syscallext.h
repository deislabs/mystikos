// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SYSCALLEXT_H
#define _MYST_SYSCALLEXT_H

#include <myst/types.h>
#include <sys/types.h>

/* myst-specific syscalls */
enum
{
    SYS_myst_trace = 1001,
    SYS_myst_trace_ptr = 1002,
    SYS_myst_dump_stack = 1003,
    SYS_myst_dump_ehdr = 1004,
    SYS_myst_dump_argv = 1005,
    SYS_myst_add_symbol_file = 1006,
    SYS_myst_load_symbols = 1007,
    SYS_myst_unload_symbols = 1008,
    SYS_myst_gen_creds = 1009,
    SYS_myst_free_creds = 1010,
    SYS_myst_verify_cert = 1011,
    SYS_myst_clone = 1012,
    SYS_myst_gcov_init = 1013,
    SYS_myst_max_threads = 1014,
    SYS_myst_poll_wake = 1015,
    SYS_myst_run_itimer = 1016,
    SYS_myst_start_shell = 1017,

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
};

#endif /* _MYST_SYSCALLEXT_H */
