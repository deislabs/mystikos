// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <elf.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <myst/backtrace.h>
#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/kernel.h>
#include <myst/printf.h>
#include <myst/stack.h>

MYST_NOINLINE
size_t myst_backtrace_impl(void** start_frame, void** buffer, size_t size)
{
    void** frame = start_frame;
    size_t n = 0;

    while (n < size)
    {
        /*
        Checks:
        - frame address lies in some kstack
        - return address - frame[1], lies within kernel
        */
        if (!myst_within_stack(frame) || !myst_is_addr_within_kernel(frame[1]))
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

size_t myst_backtrace3(void** start_frame, void** buffer, size_t size)
{
    return myst_backtrace_impl(start_frame, buffer, size);
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
    if (__myst_kernel_args.tee_debug_mode)
    {
        for (size_t i = 0; i < size; i++)
        {
            const uint64_t addr = (uint64_t)buffer[i];
            const char* name;

            if (_addr_to_func_name(addr, &name) == 0)
                myst_eprintf("%p: %s()\n", buffer[i], name);
            else
                myst_eprintf("%p: <unknown address>\n", buffer[i]);
        }
    }
}

bool myst_backtrace_contains(
    const void* const* buffer,
    size_t size,
    const char* func)
{
    for (size_t i = 0; i < size; i++)
    {
        const uint64_t addr = (uint64_t)buffer[i];
        const char* name;

        if (!addr)
            break;

        if (_addr_to_func_name(addr, &name) == 0 && strcmp(name, func) == 0)
            return true;
    }

    return false;
}
