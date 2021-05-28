// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/thread.h>

extern myst_run_thread_t __myst_run_thread;

long myst_run_thread(uint64_t cookie, uint64_t event, pid_t target_tid)
{
    return (*__myst_run_thread)(cookie, event, target_tid);
}
