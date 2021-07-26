
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
    MYST_MESSAGE_PING,
    MYST_MESSAGE_SHUTDOWN,
    MYST_MESSAGE_MOUNT_RESOLVE,
} myst_message_type_t;

typedef struct myst_mount_resolve_request
{
    uint64_t __unused;
    char path[];
} myst_mount_resolve_request_t;

typedef struct myst_mount_resolve_response
{
    long ret;
    uint64_t fs_cookie;
    char suffix[];
} myst_mount_resolve_response_t;

int myst_listener_ping(void);

int myst_listener_shutdown(void);

int myst_listener_get_sock(void);

int myst_listener_call(
    myst_message_type_t message_type,
    const void* request,
    size_t request_size,
    void** response,
    size_t* response_size);

#endif /* _MYST_LISTENER_H */
