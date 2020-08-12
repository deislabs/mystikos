#include <libos/elf.h>
#include <libos/eraise.h>
#include <libos/round.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>

#define PAGE_SIZE 4096

static int _compare_segments(const void* s1, const void* s2)
{
    const elf_segment_t* seg1 = (const elf_segment_t*)s1;
    const elf_segment_t* seg2 = (const elf_segment_t*)s2;

    return (int)(seg1->vaddr - seg2->vaddr);
}

static uint64_t _round_up_to_page_size(uint64_t x)
{
    uint64_t n = PAGE_SIZE;
    return (x + n - 1) / n * n;
}

static uint64_t _round_down_to_page_size(uint64_t x)
{
    return x & ~((uint64_t)PAGE_SIZE - 1);
}

int elf_image_load(const char* path, elf_image_t* image)
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

    if (!path || !image)
        ERAISE(-EINVAL);

    assert(image && path);

    memset(image, 0, sizeof(*image));

    if (elf_load(path, &image->elf) != 0)
        ERAISE(-EINVAL);

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
            const elf_shdr_t* sh =
                elf_get_section_header(&image->elf, i);

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
            const elf_phdr_t* ph =
                elf_get_program_header(&image->elf, i);

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
        image_size = _round_up_to_page_size(hi - lo);
    }

    /* Allocate the image on a page boundary */
    {
        if (!(image_base = memalign(PAGE_SIZE, image_size)))
            ERAISE(-ENOMEM);

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
            const elf_phdr_t* ph =
                elf_get_program_header(&image->elf, i);
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
        size_t seg_next_size = _round_down_to_page_size(seg_next->vaddr);

        if ((seg->vaddr + seg->memsz) > seg_next_size)
            ERAISE(-ERANGE);
    }

    image->elf.magic = ELF_MAGIC;
    image->image_data = image_base;
    image->image_size = image_size;
    image_base = NULL;

    /* Load the relocations into memory (zero-padded to next page size) */
    if (elf_load_relocations(
            &image->elf,
            &image->reloc_data,
            &image->reloc_size) != 0)
    {
        ERAISE(-EINVAL);
    }

    ret = 0;

done:

    if (ret != 0 && image)
    {
        elf_image_free(image);
        memset(image, 0, sizeof(*image));
    }

    if (image_base)
        free(image_base);

    return ret;
}

void elf_image_free(elf_image_t* image)
{
    if (image)
    {
        if (image->elf.data)
            free(image->elf.data);

        if (image->segments)
            free(image->segments);

        if (image->image_data)
            free(image->image_data);

        memset(image, 0, sizeof(*image));
    }
}
