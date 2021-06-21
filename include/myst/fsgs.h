// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_FSGS_H
#define _MYST_FSGS_H

#include <myst/types.h>

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

void* myst_get_fsbase(void);

void myst_set_fsbase(void* p);

void* myst_get_gsbase(void);

void myst_set_gsbase(void* p);

#endif /* _MYST_FSGS_H */
