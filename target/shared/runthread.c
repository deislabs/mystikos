// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <libos/thread.h>

extern libos_run_thread_t __libos_run_thread;

long libos_run_thread(uint64_t cookie, uint64_t event)
{
    return (*__libos_run_thread)(cookie, event);
}
