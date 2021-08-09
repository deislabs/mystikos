// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_STACK_H
#define _MYST_STACK_H

#include <stdbool.h>
#include <stddef.h>

int myst_register_stack(const void* stack, size_t size);

int myst_unregister_stack(const void* stack, size_t size);

/* return true if the given address is within a registered stack */
bool myst_within_stack(const void* addr);

#endif /* _MYST_STACK_H */
