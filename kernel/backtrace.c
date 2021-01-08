// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <elf.h>
#include <errno.h>
#include <stdlib.h>

#include <myst/backtrace.h>
#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/kernel.h>
#include <myst/printf.h>

const void* _check_address(const void* ptr)
{
    const uint64_t base = (uint64_t)__myst_kernel_args.image_data;
    const uint64_t end = base + __myst_kernel_args.image_size;

    if ((uint64_t)ptr < base || (uint64_t)ptr >= end)
        return NULL;

    return ptr;
}

MYST_NOINLINE
size_t myst_backtrace_impl(void** start_frame, void** buffer, size_t size)
{
    void** frame = start_frame;
    size_t n = 0;

    while (n < size)
    {
        if (!_check_address(frame) || !_check_address(frame[1]))
            break;

        buffer[n++] = frame[1];
        frame = (void**)*frame;
    }

    return n;
}

size_t myst_backtrace(void** buffer, size_t size)
{
    return myst_backtrace_impl(__builtin_frame_address(0), buffer, size);
}

static int _symtab_get_string(
    const void* strtab_data,
    size_t strtab_size,
    size_t offset,
    const char** name)
{
    int ret = 0;

    if (!strtab_data || !strtab_size || offset >= strtab_size || !name)
        ERAISE(-EINVAL);

    *name = (const char*)strtab_data + offset;

done:
    return ret;
}

static int _symtab_find_name(
    const void* symtab,
    size_t symtab_size,
    const void* strtab,
    size_t strtab_size,
    uint64_t addr,
    const char** name)
{
    int ret = 0;
    const Elf64_Sym* s = symtab;
    size_t n = symtab_size / sizeof(Elf64_Sym);
    const uint64_t base = (uint64_t)__myst_kernel_args.kernel_data;
    const uint64_t end = base + __myst_kernel_args.kernel_size;

    if (name)
        *name = '\0';

    if (!symtab || !strtab || !addr || !name)
        ERAISE(-EINVAL);

    if (addr < base || addr >= end)
        ERAISE(-EFAULT);

    for (size_t i = 0; i < n; i++)
    {
        const Elf64_Sym* p = &s[i];

        if (ELF64_ST_TYPE(p->st_info) == STT_FUNC)
        {
            const uint64_t lo = base + p->st_value;
            const uint64_t hi = lo + p->st_size;

            if (addr >= lo && addr <= hi)
            {
                ECHECK(
                    _symtab_get_string(strtab, strtab_size, p->st_name, name));
                goto done;
            }
        }
    }

    ERAISE(-ENOENT);

done:
    return ret;
}

static int _addr_to_func_name(uint64_t addr, const char** name)
{
    int ret = 0;

    /* search the symbol table */
    if (_symtab_find_name(
            __myst_kernel_args.symtab_data,
            __myst_kernel_args.symtab_size,
            __myst_kernel_args.strtab_data,
            __myst_kernel_args.strtab_size,
            addr,
            name) == 0)
    {
        goto done;
    }

    /* search the dynamic symbol table */
    if (_symtab_find_name(
            __myst_kernel_args.dynsym_data,
            __myst_kernel_args.dynsym_size,
            __myst_kernel_args.dynstr_data,
            __myst_kernel_args.dynstr_size,
            addr,
            name) == 0)
    {
        goto done;
    }

    return -ENOENT;

done:
    return ret;
}

void myst_dump_backtrace(void** buffer, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        const uint64_t addr = (uint64_t)buffer[i];
        const char* name;

        if (_addr_to_func_name(addr, &name) == 0)
            myst_eprintf("%p: %s()\n", buffer[i], name);
        else
            myst_eprintf("%p: unknown\n", buffer[i]);
    }
}
