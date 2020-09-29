#ifndef _LIBOS_KERNEL_H
#define _LIBOS_KERNEL_H

#include <libos/tcall.h>
#include <libos/types.h>

typedef struct libos_kernel_args
{
    /* The image that contains the kernel and crt etc. */
    const void* image_data;
    size_t image_size;

    /* The loaded kernel ELF image (ELF header start here) */
    const void* kernel_data;
    size_t kernel_size;

    /* Relocation entries */
    const void* reloc_data;
    size_t reloc_size;

    /* The symbol table (.symtab) section from the kernel ELF image */
    const void* symtab_data;
    size_t symtab_size;

    /* The symbol table (.dynsym) section from the kernel ELF image */
    const void* dynsym_data;
    size_t dynsym_size;

    /* The string table (.strtab) section from the kernel ELF image */
    const void* strtab_data;
    size_t strtab_size;

    /* The string table (.dynstr) section from the kernel ELF image */
    const void* dynstr_data;
    size_t dynstr_size;

    /* The arguments passed to libos */
    size_t argc;
    const char** argv;

    /* The environment*/
    size_t envc;
    const char** envp;

    /* The read-write-execute memory management pages */
    void* mman_data;
    size_t mman_size;

    /* The CPIO root file system image */
    void* rootfs_data;
    size_t rootfs_size;

    /* The C runtime image */
    void* crt_data;
    size_t crt_size;

    /* Tracing options */
    bool trace_syscalls;
    bool have_syscall_instruction;
    bool export_ramfs;

    /* The event object for the main thread */
    uint64_t event;

    /* Callback for making target-calls */
    libos_tcall_t tcall;
} libos_kernel_args_t;

typedef int (*libos_kernel_entry_t)(libos_kernel_args_t* args);

int libos_enter_kernel(libos_kernel_args_t* args);

extern libos_kernel_args_t __libos_kernel_args;

typedef struct libos_malloc_stats
{
    size_t usage;
    size_t peak_usage;
} libos_malloc_stats_t;

int libos_get_malloc_stats(libos_malloc_stats_t* stats);

int libos_find_leaks(void);

#endif /* _LIBOS_KERNEL_H */
