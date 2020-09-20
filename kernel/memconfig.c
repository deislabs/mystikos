#include <libos/defs.h>
#include <libos/kernel.h>
#include <libos/strings.h>
#include <libos/tcall.h>

static void _dump_target_stat(void)
{
    libos_target_stat_t config;
    const libos_kernel_args_t* args = &__libos_kernel_args;

    if (!args)
        libos_panic("bad argument");

    if (libos_tcall_target_stat(&config) != 0)
        libos_panic("libos_tcall_target_stat() failed");

    libos_printf("=== libos memory configuration:\n");
    libos_printf("kernel_mem_size=%zu\n", config.heap_size);
    libos_printf("user_mem_size=%zu\n", args->mman_size);
    libos_printf("rootfs_size=%zu\n", args->rootfs_size);
    libos_printf("crt_size=%zu\n", args->crt_size);
}

LIBOS_WEAK_ALIAS(_dump_target_stat, libos_dump_target_stat);

/* shorten name to make it convenient to call from debugger */
LIBOS_WEAK_ALIAS(_dump_target_stat, memconf);
