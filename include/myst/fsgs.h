// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_FSGS_H
#define _MYST_FSGS_H

#include <myst/types.h>

void* myst_get_fsbase(void);

void myst_set_fsbase(void* p);

void* myst_get_gsbase(void);

void myst_set_gsbase(void* p);

#endif /* _MYST_FSGS_H */
