// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_SIGNAL_H
#define _LIBOS_SIGNAL_H

#include <libos/thread.h>
#include <signal.h>

typedef void (*sigaction_handler_t)(int);

typedef void (*sigaction_function_t)(int, siginfo_t*, void*);

int libos_signal_init(libos_thread_t* t);

void libos_signal_free(libos_thread_t* t);

long libos_signal_sigaction(
    unsigned signum,
    const posix_sigaction_t* new_action,
    posix_sigaction_t* old_action);

long libos_signal_sigprocmask(int how, const sigset_t* set, sigset_t* oldset);

long libos_signal_process(libos_thread_t* thread);

long libos_signal_deliver(
    libos_thread_t* thread,
    unsigned signum,
    siginfo_t* siginfo);

long libos_signal_sigpending(sigset_t* set, unsigned size);

long libos_signal_clone(libos_thread_t* parent, libos_thread_t* child);

#endif /* _LIBOS_SIGNAL_H */