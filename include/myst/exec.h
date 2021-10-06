// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_EXEC_H
#define _MYST_EXEC_H

#include <elf.h>
#include <myst/kernel.h>
#include <myst/thread.h>

void myst_dump_stack(void* stack);

int myst_dump_ehdr(const void* ehdr);

int myst_exec(
    myst_thread_t* thread,
    const void* crt_data,
    size_t crt_size,
    const void* crt_reloc_data,
    size_t crt_reloc_size,
    size_t argc,
    const char* argv[],
    size_t envc,
    const char* envp[],
    myst_wanted_secrets_t* wanted_secrets,
    void (*callback)(void*),
    void* callback_arg);

#endif /* _MYST_EXEC_H */
