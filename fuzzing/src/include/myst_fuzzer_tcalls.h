// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

typedef enum myst_fuzzer_tcall_number
{
    SYS_myst_fuzz_get_fuzzer_payload = 2999,
    MYST_TCALL_GET_TPC,
    MYST_TCALL_SYMBOLIZER,
    MYST_TCALL_DLSYM,
    MYST_TCALL_DIE,
    MYST_TCALL_BACKTRACE,
    MYST_TCALL_BACKTRACE_SYMBOLS,
    MYST_TCALL_GETRLIMIT,
    MYST_TCALL_PTHREAD_KEY_CREATE,
    MYST_TCALL_PTHREAD_KEY_DELETE,
    MYST_TCALL_PTHREAD_SET_SPECIFIC,
    MYST_TCALL_PTHREAD_GET_SPECIFIC,
    MYST_TCALL_PTHREAD_MUTEX_LOCK,
    MYST_TCALL_PTHREAD_MUTEX_UNLOCK,
    MYST_TCALL_PTHREAD_MUTEX_COND_WAIT,
    MYST_TCALL_PTHREAD_MUTEX_COND_SIGNAL

} myst_fuzzer_tcall_number_t;

#define HANDLE_FUZZER_TCALLS(n, params)            \
    switch (n)                                     \
    {                                              \
        case SYS_myst_fuzz_get_fuzzer_payload:     \
        case MYST_TCALL_GET_TPC:                   \
        case MYST_TCALL_SYMBOLIZER:                \
        case MYST_TCALL_DLSYM:                     \
        case MYST_TCALL_DIE:                       \
        case MYST_TCALL_BACKTRACE:                 \
        case MYST_TCALL_BACKTRACE_SYMBOLS:         \
        case MYST_TCALL_GETRLIMIT:                 \
        case MYST_TCALL_PTHREAD_KEY_CREATE:        \
        case MYST_TCALL_PTHREAD_KEY_DELETE:        \
        case MYST_TCALL_PTHREAD_SET_SPECIFIC:      \
        case MYST_TCALL_PTHREAD_GET_SPECIFIC:      \
        case MYST_TCALL_PTHREAD_MUTEX_LOCK:        \
        case MYST_TCALL_PTHREAD_MUTEX_UNLOCK:      \
        case MYST_TCALL_PTHREAD_MUTEX_COND_WAIT:   \
        case MYST_TCALL_PTHREAD_MUTEX_COND_SIGNAL: \
            return fuzzer_tcalls(n, params);       \
    }
