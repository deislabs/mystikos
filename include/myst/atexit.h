// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_ATEXIT_H
#define _MYST_ATEXIT_H

#include <myst/types.h>

int myst_atexit(void (*function)(void*), void* arg);

void myst_call_atexit_functions(void);

#endif /* _MYST_ATEXIT_H */
