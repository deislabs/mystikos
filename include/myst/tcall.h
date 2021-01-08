// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TCALL_H
#define _MYST_TCALL_H

#include <myst/defs.h>
#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

typedef enum myst_tcall_number
{
    MYST_TCALL_RANDOM = 2048,
    MYST_TCALL_ALLOCATE = 2049,
    MYST_TCALL_DEALLOCATE = 2050,
    MYST_TCALL_VSNPRINTF = 2051,
    MYST_TCALL_WRITE_CONSOLE = 2052,
    MYST_TCALL_GEN_CREDS = 2053,
    MYST_TCALL_FREE_CREDS = 2054,
    MYST_TCALL_VERIFY_CERT = 2055,
    MYST_TCALL_CLOCK_GETTIME = 2056,
    MYST_TCALL_CLOCK_SETTIME = 2057,
    MYST_TCALL_ISATTY = 2058,
    MYST_TCALL_ADD_SYMBOL_FILE = 2059,
    MYST_TCALL_LOAD_SYMBOLS = 2060,
    MYST_TCALL_UNLOAD_SYMBOLS = 2061,
    MYST_TCALL_CREATE_THREAD = 2062,
    MYST_TCALL_WAIT = 2063,
    MYST_TCALL_WAKE = 2064,
    MYST_TCALL_WAKE_WAIT = 2065,
    MYST_TCALL_EXPORT_FILE = 2066,
    MYST_TCALL_SET_RUN_THREAD_FUNCTION = 2067,
    MYST_TCALL_TARGET_STAT = 2068,
    MYST_TCALL_SET_TSD = 2069,
    MYST_TCALL_GET_TSD = 2070,
    MYST_TCALL_GET_ERRNO_LOCATION = 2071,
    MYST_TCALL_READ_CONSOLE = 2072,
    MYST_TCALL_POLL_WAKE = 2073,
} myst_tcall_number_t;

long myst_tcall(long n, long params[6]);

typedef long (*myst_tcall_t)(long n, long params[6]);

long myst_tcall_random(void* data, size_t size);

long myst_tcall_thread_self(void);

long myst_tcall_vsnprintf(
    char* str,
    size_t size,
    const char* format,
    va_list ap);

long myst_tcall_read_console(int fd, void* buf, size_t count);

long myst_tcall_write_console(int fd, const void* buf, size_t count);

long myst_tcall_create_thread(uint64_t cookie);

long myst_tcall_wait(uint64_t event, const struct timespec* timeout);

long myst_tcall_wake(uint64_t event);

long myst_tcall_wake_wait(
    uint64_t waiter_event,
    uint64_t self_event,
    const struct timespec* timeout);

long myst_tcall_export_file(const char* path, const void* data, size_t size);

long myst_tcall_add_symbol_file(
    const void* file_data,
    size_t file_size,
    const void* text_data,
    size_t text_size);

long myst_tcall_load_symbols(void);

long myst_tcall_unload_symbols(void);

typedef long (*myst_run_thread_t)(uint64_t cookie, uint64_t event);

long myst_tcall_set_run_thread_function(myst_run_thread_t function);

/* for getting statistical information from the target */
typedef struct myst_target_stat
{
    uint64_t heap_size; /* 0 indicates unbounded */
} myst_target_stat_t;

long myst_tcall_target_stat(myst_target_stat_t* buf);

/* set the thread-specific-data slot in the target (only one slot) */
long myst_tcall_set_tsd(uint64_t value);

/* get the thread-specific-data slot in the target (only one slot) */
long myst_tcall_get_tsd(uint64_t* value);

/* get the address of the thread-specific errno variable */
long myst_tcall_get_errno_location(int** ptr);

/* break out of poll() */
long myst_tcall_poll_wake(void);

long myst_tcall_poll(struct pollfd* fds, nfds_t nfds, int timeout);

#endif /* _MYST_TCALL_H */
