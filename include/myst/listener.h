// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_LISTENER_H
#define _MYST_LISTENER_H

#include <myst/defs.h>
#include <myst/fs.h>
#include <myst/types.h>

typedef enum myst_message_type
{
    MYST_MESSAGE_NONE,
    MYST_MESSAGE_WAKE,
    MYST_MESSAGE_PING,
    MYST_MESSAGE_SHUTDOWN,
    MYST_MESSAGE_MOUNT_RESOLVE,
    MYST_MESSAGE_STAT,
    MYST_MESSAGE_LSTAT,
    MYST_MESSAGE_SYMLINK,
    MYST_MESSAGE_OPEN,
    MYST_MESSAGE_READ,
    MYST_MESSAGE_FSTAT,
    MYST_MESSAGE_FCNTL,
    MYST_MESSAGE_PREAD,
    MYST_MESSAGE_REALPATH,
    MYST_MESSAGE_UNLINK,
    MYST_MESSAGE_CLOSE,
    MYST_MESSAGE_WRITE,
    MYST_MESSAGE_PWRITE,
    MYST_MESSAGE_LSEEK,
    MYST_MESSAGE_ACCESS,
    MYST_MESSAGE_LINK,
    MYST_MESSAGE_RENAME,
    MYST_MESSAGE_TRUNCATE,
    MYST_MESSAGE_MKDIR,
    MYST_MESSAGE_RMDIR,
    MYST_MESSAGE_CHMOD,
    MYST_MESSAGE_FTRUNCATE,
    MYST_MESSAGE_IOCTL,
    MYST_MESSAGE_GET_EVENTS,
    MYST_MESSAGE_TARGET_FD,
    MYST_MESSAGE_FUTIMENS,
    MYST_MESSAGE_FCHOWN,
    MYST_MESSAGE_LCHOWN,
    MYST_MESSAGE_CHOWN,
    MYST_MESSAGE_FCHMOD,
    MYST_MESSAGE_FDATASYNC,
    MYST_MESSAGE_FSYNC,
    MYST_MESSAGE_STATFS,
    MYST_MESSAGE_FSTATFS,
    MYST_MESSAGE_GETDENTS64,
    MYST_MESSAGE_READLINK,
    MYST_MESSAGE_GENERATE_TID,
    MYST_MESSAGE_WRITE_PIPE,
    MYST_MESSAGE_READ_PIPE,
    MYST_MESSAGE_CLOSE_PIPE,
    MYST_MESSAGE_FSTAT_PIPE,
    MYST_MESSAGE_FCNTL_PIPE,
    MYST_MESSAGE_DUP_PIPE,
} myst_message_type_t;

int myst_listener_ping(void);

long myst_listener_wake(uint64_t addr);

int myst_listener_shutdown(void);

pid_t myst_listener_generate_tid(void);

int myst_listener_get_sock(void);

int myst_listener_call(
    myst_message_type_t message_type,
    const void* request,
    size_t request_size,
    void** response,
    size_t* response_size);

long myst_call_listener_helper(
    myst_message_type_t mt,
    const void* req,
    size_t req_size,
    size_t rsp_struct_size,
    void** rsp_out,
    size_t* rsp_size_out);

/* base type for all responses */
typedef struct myst_response
{
    long retval;
} myst_response_t;

typedef struct myst_wake_request
{
    uint64_t addr;
} myst_wake_request_t;

typedef struct myst_wake_response
{
    long retval;
} myst_wake_response_t;

typedef struct myst_mount_resolve_request
{
    uint64_t __unused;
    char path[];
} myst_mount_resolve_request_t;

typedef struct myst_mount_resolve_response
{
    long retval;
    uint64_t fs_cookie;
    char suffix[];
} myst_mount_resolve_response_t;

typedef struct myst_open_request
{
    uint64_t fs_cookie;
    int flags;
    mode_t mode;
    char pathname[];
} myst_open_request_t;

typedef struct myst_open_response
{
    long retval;
    uint64_t fs_cookie;
    uint64_t file_cookie;
} myst_open_response_t;

typedef struct myst_write_request
{
    uint64_t fs_cookie;
    uint64_t file_cookie;
    size_t count;
    size_t offset;
    uint8_t buf[];
} myst_write_request_t;

typedef struct myst_write_response
{
    long retval;
} myst_write_response_t;

typedef union myst_pathop_args {
    struct
    {
        int mode;
    } access;
    struct
    {
        off_t length;
    } truncate;
    struct
    {
        mode_t mode;
    } mkdir;
    struct
    {
        mode_t mode;
    } chmod;
    struct
    {
        uid_t owner;
        gid_t group;
    } lchown;
    struct
    {
        uid_t owner;
        gid_t group;
    } chown;
} myst_pathop_args_t;

/* request for operations that take a pathname and only input parameters */
typedef struct myst_pathop_request
{
    uint64_t fs_cookie;
    myst_pathop_args_t args;
    size_t bufsize; /* sizeof myst_pathop_response_t.buf[] */
    char pathname[];
} myst_pathop_request_t;

/* response for operations that take a pathname and only input parameters */
typedef struct myst_pathop_response
{
    long retval;
    uint8_t buf[];
} myst_pathop_response_t;

typedef union myst_fileop_args {
    struct
    {
        off_t offset;
        int whence;
    } lseek;
    struct
    {
        off_t length;
    } ftruncate;
    struct
    {
        int cmd;
        long arg;
    } fcntl;
    struct
    {
        unsigned long request;
        long arg;
    } ioctl;
    struct
    {
        struct timespec times[2];
    } futimens;
    struct
    {
        uid_t owner;
        gid_t group;
    } fchown;
    struct
    {
        mode_t mode;
    } fchmod;
    struct
    {
        off_t offset;
    } pread;
    struct
    {
        off_t offset;
    } pwrite;
} myst_fileop_args_t;

/* request for operations that take a file and only input parameters */
typedef struct myst_fileop_request
{
    uint64_t fs_cookie;
    uint64_t file_cookie;
    myst_fileop_args_t args;
    size_t inbufsize;  /* size of myst_fileop_request_t.buf[] */
    size_t outbufsize; /* size of myst_fileop_response_t.buf[] */
    uint8_t buf[];
} myst_fileop_request_t;

/* response for operations that take a file and only input parameters */
typedef struct myst_fileop_response
{
    long retval;
    uint8_t buf[];
} myst_fileop_response_t;

typedef union myst_pipeop_args {
    struct
    {
        int cmd;
        long arg;
    } fcntl;
} myst_pipeop_args_t;

/* request for operations that take a file and only input parameters */
typedef struct myst_pipeop_request
{
    uint64_t pipedev_cookie;
    uint64_t pipe_cookie;
    myst_pipeop_args_t args;
    size_t inbufsize;  /* size of myst_pipeop_request_t.buf[] */
    size_t outbufsize; /* size of myst_pipeop_response_t.buf[] */
    uint8_t buf[];
} myst_pipeop_request_t;

/* response for operations that take a file and only input parameters */
typedef struct myst_pipeop_response
{
    long retval;
    uint8_t buf[];
} myst_pipeop_response_t;

#endif /* _MYST_LISTENER_H */
