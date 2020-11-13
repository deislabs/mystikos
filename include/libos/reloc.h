// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_RELOC_H
#define _LIBOS_RELOC_H

#include <stddef.h>

int libos_apply_relocations(
    const void* image_base,
    size_t image_size,
    const void* reloc_base,
    size_t reloc_size);

#endif /* _LIBOS_RELOC_H */
