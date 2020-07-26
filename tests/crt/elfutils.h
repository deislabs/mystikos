#ifndef _OEL_ELFUTILS_H
#define _OEL_ELFUTILS_H

#include <elf.h>

const char* elf64_at_string(uint64_t value);

const char* elf64_pt_string(uint64_t value);

void elf_dump_stack(void* stack);

int elf_init_stack(
    int argc,
    const char* argv[],
    size_t envc,
    const char* envp[],
    size_t auxc,
    const Elf64_auxv_t* auxv,
    void* stack, /* 16-byte aligned data */
    size_t stack_size,
    void** sp_out);

int elf_check_stack(const void* stack, size_t stack_size);

int elf_dump_ehdr(const void* ehdr);

#endif /* _OEL_ELFUTILS_H */
