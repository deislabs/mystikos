#ifndef _LIBOS_EXEC_H
#define _LIBOS_EXEC_H

#include <elf.h>
#include <libos/thread.h>

void libos_dump_stack(void* stack);

int libos_dump_ehdr(const void* ehdr);

int libos_exec(
    libos_thread_t* thread,
    const void* crt_data,
    size_t crt_size,
    const void* crt_reloc_data,
    size_t crt_reloc_size,
    size_t argc,
    const char* argv[],
    size_t envc,
    const char* envp[]);

#endif /* _LIBOS_EXEC_H */
