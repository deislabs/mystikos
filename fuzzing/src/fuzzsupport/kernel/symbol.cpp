// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <elf.h>
#include <errno.h>
#include <link.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <map>

extern "C"
{
    void* get_kernel_args_symtab_data();
    uint64_t get_kernel_args_symtab_size();
    void* get_kernel_args_kernel_data();
    uint64_t get_kernel_args_kernel_size();
    void* get_kernel_args_strtab_data();
    uint64_t get_kernel_args_strtab_size();
}

int _symtab_get_string(
    const void* strtab_data,
    size_t strtab_size,
    size_t offset,
    char** name)
{
    int ret = 0;

    if (!strtab_data || !strtab_size || offset >= strtab_size || !name)
        return -1;

    *name = (char*)strtab_data + offset;

done:
    return ret;
}

__attribute__((no_sanitize("enclaveaddress"))) void* kernel_dlsym(
    void* handle,
    const char* name,
    void* sym_addr)
{
    static std::map<std::string, uint64_t> sym_map;
    if (sym_map.empty())
    {
        const Elf64_Sym* s = (const Elf64_Sym*)get_kernel_args_symtab_data();
        size_t n = get_kernel_args_symtab_size() / sizeof(Elf64_Sym);
        const uint64_t base = (uint64_t)get_kernel_args_kernel_data();
        const uint64_t end = base + get_kernel_args_kernel_size();

        for (size_t i = 0; i < n; i++)
        {
            const Elf64_Sym* p = &s[i];

            if (!p->st_info)
                continue;

            if (ELF64_ST_TYPE(p->st_info) == STT_FUNC)
            {
                uint64_t lo = base + p->st_value;
                uint64_t hi = lo + p->st_size;

                char* sym_name;
                _symtab_get_string(
                    get_kernel_args_strtab_data(),
                    get_kernel_args_strtab_size(),
                    p->st_name,
                    &sym_name);
                if (!sym_name || !strlen(sym_name))
                    continue;
                sym_map.insert({sym_name, lo});
            }
        }
    }

    void* ret_val = NULL;
    auto it = sym_map.find(name);
    if (it != sym_map.end())
        ret_val = (void*)it->second;

    return ret_val;
}

int _dl_iterate_phdr(
    int (*callback)(struct dl_phdr_info* info, size_t size, void* data),
    void* data)
{
    const Elf64_Ehdr* ehdr = (Elf64_Ehdr*)get_kernel_args_kernel_data();

    const uint8_t ident[] = {0x7f, 'E', 'L', 'F'};

    if (memcmp(ehdr->e_ident, ident, sizeof(ident)) != 0)
    {
        return -1;
    }

    struct dl_phdr_info info;
    memset(&info, 0, sizeof(info));
    info.dlpi_addr = (Elf64_Addr)get_kernel_args_kernel_data();
    info.dlpi_name = "";
    info.dlpi_phdr = (Elf64_Phdr*)((uint8_t*)ehdr + ehdr->e_phoff);
    info.dlpi_phnum = ehdr->e_phnum;

    return callback(&info, sizeof(info), data);
}
