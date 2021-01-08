// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_RELOC_H
#define _MYST_RELOC_H

#include <stddef.h>

int myst_apply_relocations(
    const void* image_base,
    size_t image_size,
    const void* reloc_base,
    size_t reloc_size);

#endif /* _MYST_RELOC_H */
