// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_REFSTR_H
#define _MYST_REFSTR_H

#include <stdint.h>

#include <myst/defs.h>
#include <myst/spinlock.h>

/* reference-counted string type */
typedef struct myst_refstr
{
    _Atomic(uint64_t) count;
    char data[];
} myst_refstr_t;

myst_refstr_t* myst_refstr_dup(const char* s);

void myst_refstr_ref(myst_refstr_t* refstr);

void myst_refstr_unref(myst_refstr_t* refstr);

#endif /* _MYST_REFSTR_H */
