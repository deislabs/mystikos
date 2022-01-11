// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <openenclave/enclave.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/globals.h>
#include <stdint.h>
#include <stdlib.h>
#include "fuzzsupport_t.h"
#include "myst_fuzzer_tcalls.h"
#include "pthread.h"
#include "syscall.h"
#include "syscallfuzzer.h"

__attribute__((visibility("default"))) uint64_t __sanitizer_get_host_tpc()
{
    uint64_t tpc = 0;
    oe_get_tpc_ocall(&tpc);
    return tpc;
}

__attribute__((visibility("default"))) void __asan_send_command_to_symbolizer(
    uint64_t module_offset,
    char** symbol)
{
    oe_llvm_symbolize_ocall(oe_get_enclave(), module_offset, symbol);
}

__attribute__((visibility("default"))) void __sanitizer_die()
{
    oe_die_ocall();
}

void* __dlsym(
    void* restrict handle,
    const char* restrict name,
    void* restrict sym_addr)
{
    void* ret = NULL;
    oe_result_t result = OE_UNEXPECTED;
    OE_UNUSED(handle);
    OE_UNUSED(sym_addr);

    uint64_t offset = 0ULL;
    if (oe_get_symbol_offset_ocall(&result, oe_get_enclave(), name, &offset) !=
        OE_OK)
        goto done;

    if (result != OE_OK)
        goto done;

    const uint8_t* baseaddr = (const uint8_t*)__oe_get_enclave_base_address();
    uint64_t* dest = (uint64_t*)(baseaddr + offset);

    ret = (void*)dest;

    size_t enc_size = __oe_get_heap_size();
    enc_size = enc_size;

done:
    return ret;
}

long fuzzer_tcalls(long n, long params[6])
{
    long ret = -1;
    switch (n)
    {
        case MYST_TCALL_GET_TPC:
            ret = __sanitizer_get_host_tpc();
            break;
        case MYST_TCALL_SYMBOLIZER:
            oe_kernel_llvm_symbolize_ocall(
                (uint64_t)params[0], (char**)params[1]);
            ret = 0;
            break;
        case MYST_TCALL_DLSYM:
            ret = (long)__dlsym(
                (void*)params[0], (const char*)params[1], (void*)params[2]);
            break;
        case MYST_TCALL_DIE:
            __sanitizer_die();
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
            ret = oe_SYS_getrlimit_impl(params[0], params[1]);
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
            oe_get_syscall_fuzzer_payload_ocall(&syscall_payload_ptr);
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

int getpwnam_r(
    const char* name,
    struct passwd* pw,
    char* buf,
    size_t size,
    struct passwd** res)
{
    return 0;
}

int getpwuid_r(
    unsigned uid,
    struct passwd* pw,
    char* buf,
    size_t size,
    struct passwd** res)
{
    return 0;
}

int lstat(const char* restrict path, struct stat* restrict buf)
{
    return 0;
}

void _pthread_cleanup_push(struct __ptcb* cb, void (*f)(void*), void* x)
{
}

void _pthread_cleanup_pop(struct __ptcb* cb, int run)
{
}