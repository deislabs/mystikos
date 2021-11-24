// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_INVOKE_H
#define _MYST_INVOKE_H

#include <stddef.h>

typedef long (*myst_invoke_func_t)(long arg0, ...);

/* Invoke the given function on a stack of the given size (in bytes) */
long myst_invoke(size_t stack_size, myst_invoke_func_t func, ...);

#endif /* _MYST_INVOKE_H */
