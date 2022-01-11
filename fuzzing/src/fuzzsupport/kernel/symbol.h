// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <stdlib.h>
#include <string.h>

void* kernel_dlsym(void* handle, const char* name, void* sym_addr);
int _dl_iterate_phdr(
    int (*callback)(struct dl_phdr_info* info, size_t size, void* data),
    void* data);