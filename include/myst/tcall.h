// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TCALL_H
#define _MYST_TCALL_H

#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include <myst/blockdevice.h>
#include <myst/defs.h>
#include <myst/fssig.h>

typedef enum myst_tcall_number
{
    MYST_TCALL_RANDOM = 2048,
    MYST_TCALL_VSNPRINTF,
    MYST_TCALL_WRITE_CONSOLE,
    MYST_TCALL_GEN_CREDS,
    MYST_TCALL_FREE_CREDS,
    MYST_TCALL_VERIFY_CERT,
    MYST_TCALL_GEN_CREDS_EX,
    MYST_TCALL_CLOCK_GETTIME,
    MYST_TCALL_CLOCK_SETTIME,
    MYST_TCALL_ISATTY,
    MYST_TCALL_ADD_SYMBOL_FILE,
    MYST_TCALL_LOAD_SYMBOLS,
    MYST_TCALL_UNLOAD_SYMBOLS,
    MYST_TCALL_CREATE_THREAD,
    MYST_TCALL_WAIT,
    MYST_TCALL_WAKE,
    MYST_TCALL_WAKE_WAIT,
    MYST_TCALL_EXPORT_FILE,
    MYST_TCALL_SET_RUN_THREAD_FUNCTION,
    MYST_TCALL_TARGET_STAT,
    MYST_TCALL_SET_TSD,
    MYST_TCALL_GET_TSD,
    MYST_TCALL_GET_ERRNO_LOCATION,
    MYST_TCALL_READ_CONSOLE,
    MYST_TCALL_POLL_WAKE,
    MYST_TCALL_OPEN_BLOCK_DEVICE,
    MYST_TCALL_CLOSE_BLOCK_DEVICE,
    MYST_TCALL_READ_BLOCK_DEVICE,
    MYST_TCALL_WRITE_BLOCK_DEVICE,
    MYST_TCALL_LUKS_ENCRYPT,
    MYST_TCALL_LUKS_DECRYPT,
    MYST_TCALL_SHA256_START,
    MYST_TCALL_SHA256_UPDATE,
    MYST_TCALL_SHA256_FINISH,
    MYST_TCALL_VERIFY_SIGNATURE,
    MYST_TCALL_LOAD_FSSIG,
    MYST_TCALL_CLOCK_GETRES,
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

typedef long (
    *myst_run_thread_t)(uint64_t cookie, uint64_t event, pid_t target_tid);

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

int myst_tcall_open_block_device(const char* path, bool read_only);

int myst_tcall_close_block_device(int blkdev);

int myst_tcall_write_block_device(
    int blkdev,
    uint64_t blkno,
    const struct myst_block* blocks,
    size_t num_blocks);

int myst_tcall_read_block_device(
    int blkdev,
    uint64_t blkno,
    struct myst_block* blocks,
    size_t num_blocks);

int myst_tcall_verify_signature(
    const char* pem_public_key,
    const uint8_t* hash,
    size_t hash_size,
    const uint8_t* signer,
    size_t signer_size,
    const uint8_t* signature,
    size_t signature_size);

int myst_tcall_load_fssig(const char* path, myst_fssig_t* fssig);

#endif /* _MYST_TCALL_H */
