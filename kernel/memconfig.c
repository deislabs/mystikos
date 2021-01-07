// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>

#include <myst/kernel.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/strings.h>
#include <myst/tcall.h>

static void _dump_target_stat(void)
{
    myst_target_stat_t config;
    const myst_kernel_args_t* args = &__myst_kernel_args;

    if (!args)
        myst_panic("bad argument");

    if (myst_tcall_target_stat(&config) != 0)
        myst_panic("myst_tcall_target_stat() failed");

    printf("=== myst memory configuration:\n");
    printf("kernel_mem_size=%zu\n", config.heap_size);
    printf("user_mem_size=%zu\n", args->mman_size);
    printf("rootfs_size=%zu\n", args->rootfs_size);
    printf("crt_size=%zu\n", args->crt_size);
}

MYST_WEAK_ALIAS(_dump_target_stat, myst_dump_target_stat);

/* shorten name to make it convenient to call from debugger */
MYST_WEAK_ALIAS(_dump_target_stat, memconf);
