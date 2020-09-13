#include <elf.h>
#include <assert.h>

#include <libos/reloc.h>
#include <libos/eraise.h>

int libos_apply_relocations(
    const void* image_base,
    size_t image_size,
    const void* reloc_base,
    size_t reloc_size)
{
    int ret = 0;
    const Elf64_Rela* relocs = (const Elf64_Rela*)reloc_base;
    size_t nrelocs = reloc_size / sizeof(Elf64_Rela);
    const uint8_t* baseaddr = (const uint8_t*)image_base;

    for (size_t i = 0; i < nrelocs; i++)
    {
        const Elf64_Rela* p = &relocs[i];

        /* If zero-padded bytes reached */
        if (p->r_offset == 0)
            break;

        if (!(p->r_offset > 0))
            ERAISE(-EINVAL);

        if (!(p->r_offset <= image_size))
            ERAISE(-EINVAL);

        /* Compute address of reference to be relocated */
        uint64_t* dest = (uint64_t*)(baseaddr + p->r_offset);

        uint64_t reloc_type = ELF64_R_TYPE(p->r_info);

        /* Relocate the reference */
        if (reloc_type == R_X86_64_RELATIVE)
        {
            *dest = (uint64_t)(baseaddr + p->r_addend);
        }
    }

done:
    return ret;
}
