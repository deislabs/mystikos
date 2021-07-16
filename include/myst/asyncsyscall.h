// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_ASYNFDOPS_H
#define _MYST_ASYNFDOPS_H

#include <stddef.h>

// Perform an fd-oriented "asynchronous" syscall that can be interrupted by
// calling myst_interrupt_async_syscall().
long myst_async_syscall(long num, int poll_flags, int fd, ...);

// Interrupt the invocation of myst_async_syscall() that is currently blocked
// on the given fd, forcing myst_async_syscall() to return -EINTR.
long myst_interrupt_async_syscall(int fd);

#endif /* _MYST_ASYNFDOPS_H */
