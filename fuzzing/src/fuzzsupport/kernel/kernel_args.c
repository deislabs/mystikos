// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "myst/kernel.h"

void* get_kernel_args_symtab_data()
{
    return __myst_kernel_args.symtab_data;
}

uint64_t get_kernel_args_symtab_size()
{
    return __myst_kernel_args.symtab_size;
}

void* get_kernel_args_kernel_data()
{
    return __myst_kernel_args.kernel_data;
}

uint64_t get_kernel_args_kernel_size()
{
    return __myst_kernel_args.kernel_size;
}

void* get_kernel_args_strtab_data()
{
    return __myst_kernel_args.strtab_data;
}

uint64_t get_kernel_args_strtab_size()
{
    return __myst_kernel_args.strtab_size;
}
