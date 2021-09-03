// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_ASYNTCALL_H
#define _MYST_ASYNTCALL_H

#include <stddef.h>

// Perform an fd-oriented tcall that can be asynchronously interrupted by
// myst_interrupt_async_tcall().
long myst_async_tcall(long num, int poll_flags, int fd, ...);

// Interrupt the invocation of myst_async_tcall() that is currently blocked
// on the given fd causing it to return -EINTR.
long myst_interrupt_async_tcall(int fd);

#endif /* _MYST_ASYNTCALL_H */
