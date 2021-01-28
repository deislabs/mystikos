// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <malloc.h>
#include <myst/elf.h>
#include <myst/eraise.h>
#include <myst/round.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static int _compare_segments(const void* s1, const void* s2)
{
    const elf_segment_t* seg1 = (const elf_segment_t*)s1;
    const elf_segment_t* seg2 = (const elf_segment_t*)s2;

    return (int)(seg1->vaddr - seg2->vaddr);
}

static int _process_elf_image(elf_image_t* image)
{
    int ret = -1;
    const elf_ehdr_t* eh;
    size_t num_segments;
    /* ATTN:MEB: determine which of these are needed later */
    uint64_t entry_rva = 0;
    uint64_t text_rva = 0;
    uint64_t tdata_rva = 0;
    uint64_t tdata_size = 0;
    uint64_t tdata_align = 0;
    uint64_t image_size = 0;
    char* image_base = NULL;
    uint64_t tbss_size = 0;
    uint64_t tbss_align = 0;

    (void)entry_rva;
    (void)tdata_align;
    (void)tbss_align;
    (void)tbss_size;

    if (!image)
        ERAISE(-EINVAL);

    assert(image);

    /* Save pointer to header for convenience */
    eh = (elf_ehdr_t*)image->elf.data;

    /* Fail if not Intel X86 64-bit */
    if (eh->e_machine != EM_X86_64)
        ERAISE(-EINVAL);

    /* Fail if image is relocatable */
    if (eh->e_type == ET_REL)
        ERAISE(-EINVAL);

    /* Save entry point address */
    entry_rva = eh->e_entry;

    // Obtain the given values from the following sections:
    //     .text  : text_rva
    //     .tdata : tdata_rva, tdata_size, tdata_align
    //     .tbss  : tbss_size, tbss_align
    {
        for (size_t i = 0; i < eh->e_shnum; i++)
        {
            const elf_shdr_t* sh = elf_get_section_header(&image->elf, i);

            /* Invalid section header. The elf file is corrupted. */
            if (sh == NULL)
                ERAISE(-EINVAL);

            const char* name =
                elf_get_string_from_shstrtab(&image->elf, sh->sh_name);

            if (name)
            {
                if (strcmp(name, ".text") == 0)
                {
                    text_rva = sh->sh_addr;
                }
                else if (strcmp(name, ".tdata") == 0)
                {
                    // These items must match program header values.
                    tdata_rva = sh->sh_addr;
                    tdata_size = sh->sh_size;
                    tdata_align = sh->sh_addralign;
                }
                else if (strcmp(name, ".tbss") == 0)
                {
                    tbss_size = sh->sh_size;
                    tbss_align = sh->sh_addralign;
                }
            }
        }

        /* Fail if required sections not found */
        if (text_rva == 0)
        {
            ERAISE(-EINVAL);
        }
    }

    // Scan program headers to find the image size and the number of segments.
    // Outputs: image_size, num_segments
    {
        uint64_t lo = 0xFFFFFFFFFFFFFFFF; /* lowest address of all segments */
        uint64_t hi = 0;                  /* highest address of all segments */
        num_segments = 0;

        for (size_t i = 0; i < eh->e_phnum; i++)
        {
            const elf_phdr_t* ph = elf_get_program_header(&image->elf, i);

            /* Check for corrupted program header. */
            if (ph == NULL)
                ERAISE(-EINVAL);

            /* Check for proper sizes for the program segment. */
            if (ph->p_filesz > ph->p_memsz)
                ERAISE(-EINVAL);

            switch (ph->p_type)
            {
                case PT_LOAD:
                {
                    if (lo > ph->p_vaddr)
                        lo = ph->p_vaddr;

                    if (hi < ph->p_vaddr + ph->p_memsz)
                        hi = ph->p_vaddr + ph->p_memsz;

                    num_segments++;
                    break;
                }
                default:
                    break;
            }
        }

        /* Fail if LO not found */
        if (lo != 0)
            ERAISE(-EINVAL);

        /* Fail if HI not found */
        if (hi == 0)
            ERAISE(-EINVAL);

        /* Fail if no segment found */
        if (num_segments == 0)
            ERAISE(-EINVAL);

        /* Calculate the full size of the image (rounded up to the page size) */
        ECHECK(myst_round_up(hi - lo, PAGE_SIZE, &image_size));
    }

    /* Allocate the image on a page boundary */
    {
        int prot = PROT_READ | PROT_WRITE;
        int flags = MAP_ANONYMOUS | MAP_PRIVATE;
        void* addr;

        if ((addr = mmap(NULL, image_size, prot, flags, -1, 0)) == MAP_FAILED)
            ERAISE(-ENOMEM);

        image_base = addr;

        /* Clear the image memory */
        memset(image_base, 0, image_size);
    }

    /* Allocate the segments array */
    {
        elf_segment_t* segments;
        const size_t alloc_size = num_segments * sizeof(elf_segment_t);

        if (!(segments = memalign(PAGE_SIZE, alloc_size)))
            ERAISE(-ENOMEM);

        memset(segments, 0, alloc_size);

        image->segments = segments;
        image->num_segments = num_segments;
    }

    /* Copy all loadable program segments to segments array */
    {
        size_t n = 0;

        /* For each program header */
        for (size_t i = 0; i < eh->e_phnum; i++)
        {
            const elf_phdr_t* ph = elf_get_program_header(&image->elf, i);
            elf_segment_t* seg = &image->segments[n];
            void* segdata;

            assert(ph);
            assert(ph->p_filesz <= ph->p_memsz);

            if (ph->p_type == PT_TLS)
            {
                if (tdata_rva != ph->p_vaddr)
                {
                    if (tdata_rva != 0)
                        ERAISE(-EINVAL);
                }

                if (tdata_size != ph->p_filesz)
                {
                    ERAISE(-EINVAL);
                }
                continue;
            }

            /* Skip non-loadable program segments */
            if (ph->p_type != PT_LOAD)
                continue;

            /* Save these segment fields */
            seg->memsz = ph->p_memsz;
            seg->filesz = ph->p_filesz;
            seg->offset = ph->p_offset;
            seg->vaddr = ph->p_vaddr;
            seg->filedata = (unsigned char*)image->elf.data + seg->offset;

            /* Translate the segment flags */
            {
                if (ph->p_flags & PF_R)
                    seg->flags |= PF_R;

                if (ph->p_flags & PF_W)
                    seg->flags |= PF_W;

                if (ph->p_flags & PF_X)
                    seg->flags |= PF_X;
            }

            /* Copy the segment to the image */
            if ((segdata = elf_get_segment(&image->elf, i)))
                memcpy(image_base + seg->vaddr, segdata, seg->filesz);

            n++;
        }

        assert(n == num_segments);
    }

    /* Sort the segments array by their vaddr field */
    qsort(
        image->segments,
        image->num_segments,
        sizeof(elf_segment_t),
        _compare_segments);

    /* Check that each segment does not overlap the next segmehnt */
    for (size_t i = 0; i < image->num_segments - 1; i++)
    {
        const elf_segment_t* seg = &image->segments[i];
        const elf_segment_t* seg_next = &image->segments[i + 1];
        size_t seg_next_size = myst_round_down_to_page_size(seg_next->vaddr);

        if ((seg->vaddr + seg->memsz) > seg_next_size)
            ERAISE(-ERANGE);
    }

    /* Set memory permissions for each segment */
    for (size_t i = 0; i < image->num_segments; i++)
    {
        const elf_segment_t* segment = &image->segments[i];
        const uint64_t vaddr = myst_round_down_to_page_size(segment->vaddr);
        void* addr = (uint8_t*)image_base + vaddr;
        int prot = 0;

        if (segment->flags & PF_R)
            prot |= PROT_READ;

        if (segment->flags & PF_W)
            prot |= PROT_WRITE;

        if (segment->flags & PF_X)
            prot |= PROT_EXEC;

        if (mprotect(addr, segment->memsz, prot) != 0)
            ERAISE(-errno);
    }

    image->elf.magic = ELF_MAGIC;
    image->image_data = image_base;
    image->image_size = image_size;
    image_base = NULL;

    /* Load the relocations into memory (zero-padded to next page size) */
    if (elf_load_relocations(
            &image->elf, &image->reloc_data, &image->reloc_size) != 0)
    {
        ERAISE(-EINVAL);
    }

    /* Load the symbol table (.symtab) */
    {
        uint8_t* p;
        size_t n;
        void* symtab_data;
        size_t symtab_size;

        if (elf_find_section(&image->elf, ".symtab", &p, &n) != 0)
            ERAISE(-EINVAL);

        ECHECK(myst_round_up(n, PAGE_SIZE, &symtab_size));

        if (!(symtab_data = memalign(PAGE_SIZE, symtab_size)))
            ERAISE(-ENOMEM);

        memset(symtab_data, 0, symtab_size);
        memcpy(symtab_data, p, symtab_size);

        image->symtab_data = symtab_data;
        image->symtab_size = symtab_size;
    }

    /* Load the symbol table (.dynsym) */
    {
        uint8_t* p;
        size_t n;
        void* dynsym_data;
        size_t dynsym_size;

        if (elf_find_section(&image->elf, ".dynsym", &p, &n) != 0)
            ERAISE(-EINVAL);

        ECHECK(myst_round_up(n, PAGE_SIZE, &dynsym_size));

        if (!(dynsym_data = memalign(PAGE_SIZE, dynsym_size)))
            ERAISE(-ENOMEM);

        memset(dynsym_data, 0, dynsym_size);
        memcpy(dynsym_data, p, dynsym_size);

        image->dynsym_data = dynsym_data;
        image->dynsym_size = dynsym_size;
    }

    /* Load the string table (.strtab) */
    {
        uint8_t* p;
        size_t n;
        void* strtab_data = NULL;
        size_t strtab_size;

        if (elf_find_section(&image->elf, ".strtab", &p, &n) != 0)
            ERAISE(-EINVAL);

        ECHECK(myst_round_up(n, PAGE_SIZE, &strtab_size));

        if (!(strtab_data = memalign(PAGE_SIZE, strtab_size)))
            ERAISE(-ENOMEM);

        memset(strtab_data, 0, strtab_size);
        memcpy(strtab_data, p, n);

        image->strtab_data = strtab_data;
        image->strtab_size = strtab_size;
    }

    /* Load the string table (.dynstr) */
    {
        uint8_t* p;
        size_t n;
        void* dynstr_data = NULL;
        size_t dynstr_size;

        if (elf_find_section(&image->elf, ".dynstr", &p, &n) != 0)
            ERAISE(-EINVAL);

        ECHECK(myst_round_up(n, PAGE_SIZE, &dynstr_size));

        if (!(dynstr_data = memalign(PAGE_SIZE, dynstr_size)))
            ERAISE(-ENOMEM);

        memset(dynstr_data, 0, dynstr_size);
        memcpy(dynstr_data, p, n);

        image->dynstr_data = dynstr_data;
        image->dynstr_size = dynstr_size;
    }

    ret = 0;

done:

    if (ret != 0 && image)
    {
        elf_image_free(image);
        memset(image, 0, sizeof(*image));
    }

    if (image_base)
        munmap(image_base, image_size);

    return ret;
}

int elf_image_load(const char* path, elf_image_t* image)
{
    int ret = -1;

    if (!path || !image)
        ERAISE(-EINVAL);

    assert(image && path);

    memset(image, 0, sizeof(*image));

    if (elf_load(path, &image->elf) != 0)
        ERAISE(-EINVAL);

    ret = _process_elf_image(image);

#if 0
    printf("image_size=%zu\n", image->image_size);
    printf("reloc_size=%zu\n", image->reloc_size);
    printf("symtab_size=%zu\n", image->symtab_size);
    printf("strtab_size=%zu\n", image->strtab_size);
#endif

done:
    return ret;
}

int elf_image_from_section(
    elf_image_t* from_elf,
    const char* section_name,
    elf_image_t* to_elf,
    const void** buffer_out,
    size_t* buffer_size_out)
{
    int ret = -1;
    unsigned char* buffer = NULL;
    size_t buffer_size = 0;

    if (!from_elf || !section_name || !to_elf)
        ERAISE(-EINVAL);

    assert(from_elf && section_name && to_elf);

    memset(to_elf, 0, sizeof(*to_elf));

    if (elf_find_section(&from_elf->elf, section_name, &buffer, &buffer_size) !=
        0)
        ERAISE(-EINVAL);

    if (elf_from_buffer(buffer, buffer_size, &to_elf->elf) != 0)
        ERAISE(-EINVAL);

    if (buffer_out)
        *buffer_out = buffer;

    if (buffer_size_out)
        *buffer_size_out = buffer_size;

    ret = _process_elf_image(to_elf);

done:
    return ret;
}

void elf_image_free(elf_image_t* image)
{
    if (image)
    {
        elf_unload(&image->elf);

        if (image->segments)
            free(image->segments);

        if (image->image_data)
            munmap(image->image_data, image->image_size);

        if (image->reloc_data)
            free(image->reloc_data);

        if (image->symtab_data)
            free(image->symtab_data);

        if (image->strtab_data)
            free(image->strtab_data);

        if (image->dynsym_data)
            free(image->dynsym_data);

        if (image->dynstr_data)
            free(image->dynstr_data);

        memset(image, 0, sizeof(*image));
    }
}

void elf_image_dump(const elf_image_t* image)
{
    printf("=== %s()\n", __FUNCTION__);

    if (!image)
        return;

    printf("image_data: %p\n", image->image_data);
    printf("image_size: %zu\n", image->image_size);
    printf("reloc_data: %p\n", image->reloc_data);
    printf("reloc_size: %zu\n", image->reloc_size);
    printf("symtab_data: %p\n", image->symtab_data);
    printf("symtab_size: %zu\n", image->symtab_size);
    printf("strtab_data: %p\n", image->strtab_data);
    printf("strtab_size: %zu\n", image->strtab_size);
    printf("num_segments: %zu\n", image->num_segments);
    printf("segments: %p\n", image->segments);
    printf("num_segments: %zu\n", image->num_segments);

    for (size_t i = 0; i < image->num_segments; i++)
    {
        printf("segment[%zu].filedata=%p\n", i, image->segments[i].filedata);
        printf("segment[%zu].filesz=%zu\n", i, image->segments[i].filesz);
        printf("segment[%zu].memsz=%zu\n", i, image->segments[i].memsz);
        printf("segment[%zu].offset=%lu\n", i, image->segments[i].offset);
        printf("segment[%zu].vaddr=%lu\n", i, image->segments[i].vaddr);
        printf("segment[%zu].flags=%x\n", i, image->segments[i].flags);
    }
}
