// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SIGNAL_H
#define _MYST_SIGNAL_H

#include <myst/thread.h>
#include <signal.h>

typedef void (*sigaction_handler_t)(int);

typedef void (*sigaction_function_t)(int, siginfo_t*, void*);

int myst_signal_init(myst_process_t* process);

void myst_signal_free(myst_process_t* process);
void myst_signal_free_siginfos(myst_thread_t* t);

long myst_signal_sigaction(
    unsigned signum,
    const posix_sigaction_t* new_action,
    posix_sigaction_t* old_action);

long myst_signal_sigprocmask(int how, const sigset_t* set, sigset_t* oldset);

long myst_signal_process(myst_thread_t* thread);

long myst_signal_deliver(
    myst_thread_t* thread,
    unsigned signum,
    siginfo_t* siginfo);

long myst_signal_sigpending(sigset_t* set, unsigned size);

long myst_signal_clone(myst_thread_t* parent, myst_thread_t* child);

void myst_handle_host_signal(siginfo_t* siginfo, mcontext_t* mcontext);

void myst_sigreturn(mcontext_t* mcontext_t);

int myst_signal_has_active_signals(myst_thread_t* thread);

int myst_signal_altstack(const stack_t* ss, stack_t* old_ss);

const char* myst_signum_to_string(unsigned signum);

void myst_signal_restore_mask(void);

int myst_sigfillset(sigset_t* set);

#endif /* _MYST_SIGNAL_H */
