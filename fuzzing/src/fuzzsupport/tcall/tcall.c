// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// #include <openenclave/enclave.h>
// #include <openenclave/internal/elf.h>
// #include <openenclave/internal/globals.h>
#include <stdint.h>
#include <stdlib.h>
// #include "fuzzsupport_t.h"
#include "myst_fuzzer_tcalls.h"
#include "pthread.h"
#include "syscall.h"
#include "syscallfuzzer.h"
// #include <bits/stdint-uintn.h>

extern uint64_t oe_get_syscall_fuzzer_payload_ocall();

__attribute__((visibility("default"))) void __asan_send_command_to_symbolizer(
    uint64_t module_offset,
    char** symbol)
{
    oe_llvm_symbolize_ocall(NULL, module_offset, symbol);
}

long fuzzer_tcalls(long n, long params[6])
{
    long ret = -1;
    switch (n)
    {
        case MYST_TCALL_GET_TPC:
        {
            uint64_t tpc = 0;
            oe_get_tpc_ocall(&tpc);
            ret = tpc;
        }
        break;
        case MYST_TCALL_SYMBOLIZER:
            oe_kernel_llvm_symbolize_ocall(
                (uint64_t)params[0], (char**)params[1]);
            ret = 0;
            break;
        case MYST_TCALL_DIE:
            oe_die_ocall();
            ret = 0;
            break;
        case MYST_TCALL_BACKTRACE:
            ret = (long)backtrace((void**)params[0], (int)params[1]);
            break;
        case MYST_TCALL_BACKTRACE_SYMBOLS:
            ret = (long)backtrace_symbols(
                (void* const*)params[0], (int)params[1]);
            break;
        case MYST_TCALL_GETRLIMIT:
        {
            ret = getrlimit(params[0], params[1]);
            // ret = (uint64_t)syscall(SYS_getrlimit, params[0], params[1]);
        }
        break;
        case MYST_TCALL_PTHREAD_KEY_CREATE:
            ret = pthread_key_create(params[0], params[1]);
            break;
        case MYST_TCALL_PTHREAD_KEY_DELETE:
            ret = pthread_key_delete(params[0]);
            break;
        case MYST_TCALL_PTHREAD_SET_SPECIFIC:
            ret =
                pthread_setspecific((pthread_key_t)params[0], (void*)params[1]);
            break;
        case MYST_TCALL_PTHREAD_GET_SPECIFIC:
            ret = pthread_getspecific((pthread_key_t)params[0]);
            break;
        case MYST_TCALL_PTHREAD_MUTEX_LOCK:
            ret = pthread_mutex_lock((pthread_mutex_t*)params[0]);
            break;
        case MYST_TCALL_PTHREAD_MUTEX_UNLOCK:
            ret = pthread_mutex_unlock((pthread_mutex_t*)params[0]);
            break;
        case MYST_TCALL_PTHREAD_MUTEX_COND_WAIT:
            ret = pthread_cond_wait(
                (pthread_cond_t*)params[0], (pthread_mutex_t*)params[1]);
            break;
        case MYST_TCALL_PTHREAD_MUTEX_COND_SIGNAL:
            ret = pthread_cond_signal((pthread_cond_t*)params[0]);
            break;
        case SYS_myst_fuzz_get_fuzzer_payload:
        {
            uint64_t syscall_payload_ptr = 0;
            syscall_payload_ptr = oe_get_syscall_fuzzer_payload_ocall();
            *((long*)params[0]) = (long*)syscall_payload_ptr;
            ret = (syscall_payload_ptr == 0);
            break;
        }
        default:
        {
            printf("error: handle_fuzzer_tcalls=%ld\n", n);
        }
    }
    return ret;
}
