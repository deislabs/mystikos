#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sections.h"

static ssize_t _readn(int fd, void* data, size_t size, off_t off)
{
    ssize_t ret = 0;
    unsigned char* p = (unsigned char*)data;
    size_t r = size;
    size_t m = 0;

    while (r)
    {
        ssize_t n = pread(fd, p, r, off);

        if (n > 0)
        {
            p += n;
            r -= n;
            m += n;
            off += n;
        }
        else if (n == 0)
        {
            ret = -EIO;
            goto done;
        }
        else
        {
            ret = -errno;
            goto done;
        }
    }

    ret = m;

done:
    return ret;
}

void free_sections(sections_t* sections)
{
    if (sections)
    {
        free(sections->mystenc_data);
        free(sections->libmystcrt_data);
        free(sections->libmystkernel_data);
        free(sections->mystrootfs_data);
        free(sections->mystpubkeys_data);
        free(sections->mystroothashes_data);
        free(sections->mystconfig_data);
        memset(sections, 0, sizeof(struct sections));
    }
}

int load_sections(const char* path, sections_t* sections)
{
    int ret = 0;
    int fd = -1;
    Elf64_Ehdr eh;
    const uint8_t ident[] = {0x7f, 'E', 'L', 'F'};
    Elf64_Shdr* shdrs = NULL;
    char* shstrtab = NULL;

    if (sections)
        memset(sections, 0, sizeof(struct sections));

    if (!path || !sections)
    {
        ret = -EINVAL;
        goto done;
    }

    /* open the ELF file */
    if ((fd = open(path, O_RDONLY)) < 0)
    {
        ret = -ENOENT;
        goto done;
    }

    /* read the ELF header into memory */
    if (_readn(fd, &eh, sizeof(eh), 0) != sizeof(eh))
    {
        ret = -EIO;
        goto done;
    }

    /* check the ELF magic identifier */
    if (memcmp(eh.e_ident, ident, sizeof(ident)) != 0)
    {
        ret = -EIO;
        goto done;
    }

    /* read the section table into memory */
    {
        const size_t size = (size_t)eh.e_shnum * (size_t)eh.e_shentsize;

        if (!(shdrs = malloc(size)))
        {
            ret = -ENOMEM;
            goto done;
        }

        if (_readn(fd, shdrs, size, eh.e_shoff) != size)
        {
            ret = -EIO;
            goto done;
        }

        assert(sizeof(Elf64_Shdr) == eh.e_shentsize);
    }

    /* read the shstrtab (section header string table) into memory */
    {
        const size_t size = shdrs[eh.e_shstrndx].sh_size;
        const size_t offset = shdrs[eh.e_shstrndx].sh_offset;

        if (!(shstrtab = malloc(size)))
        {
            ret = -ENOMEM;
            goto done;
        }

        if (_readn(fd, shstrtab, size, offset) != size)
        {
            ret = -EIO;
            goto done;
        }
    }

    /* load the selected sections */
    for (size_t i = 0; i < eh.e_shnum; i++)
    {
        Elf64_Shdr* sh = &shdrs[i];
        const char* name = &shstrtab[sh->sh_name];
        const size_t size = sh->sh_size;
        const size_t offset = sh->sh_offset;
        void** data_ptr = NULL;

        if (strcmp(name, ".mystenc") == 0)
        {
            data_ptr = &sections->mystenc_data;
            sections->mystenc_size = size;
        }
        else if (strcmp(name, ".libmystcrt") == 0)
        {
            data_ptr = &sections->libmystcrt_data;
            sections->libmystcrt_size = size;
        }
        else if (strcmp(name, ".libmystkernel") == 0)
        {
            data_ptr = &sections->libmystkernel_data;
            sections->libmystkernel_size = size;
        }
        else if (strcmp(name, ".mystrootfs") == 0)
        {
            data_ptr = &sections->mystrootfs_data;
            sections->mystrootfs_size = size;
        }
        else if (strcmp(name, ".mystpubkeys") == 0)
        {
            data_ptr = &sections->mystpubkeys_data;
            sections->mystpubkeys_size = size;
        }
        else if (strcmp(name, ".mystroothashes") == 0)
        {
            data_ptr = &sections->mystroothashes_data;
            sections->mystroothashes_size = size;
        }
        else if (strcmp(name, ".mystconfig") == 0)
        {
            data_ptr = &sections->mystconfig_data;
            sections->mystconfig_size = size;
        }

        if (data_ptr)
        {
            if (!(*data_ptr = malloc(size)))
            {
                ret = -ENOMEM;
                goto done;
            }

            if (_readn(fd, *data_ptr, size, offset) != size)
            {
                ret = -EIO;
                goto done;
            }
        }
    }

    /* verify that all the expected sections were loaded */
    if (!sections->mystenc_data || !sections->libmystcrt_data ||
        !sections->libmystkernel_data || !sections->mystrootfs_data ||
        !sections->mystpubkeys_data || !sections->mystroothashes_data ||
        !sections->mystconfig_data)
    {
        ret = -EIO;
        goto done;
    }

done:

    if (fd >= 0)
        close(fd);

    if (shdrs)
        free(shdrs);

    if (shstrtab)
        free(shstrtab);

    if (ret != 0 && sections)
        free_sections(sections);

    return ret;
}
