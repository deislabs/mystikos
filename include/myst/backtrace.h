// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_BACKTRACE_H
#define _MYST_BACKTRACE_H

#include <stdbool.h>
#include <stddef.h>

size_t myst_backtrace3(void** start_frame, void** buffer, size_t size);

size_t myst_backtrace(void** buffer, size_t size);

void myst_dump_backtrace(void** buffer, size_t size);

/* return true if the backtrace contains the given function */
bool myst_backtrace_contains(
    const void* const* buffer,
    size_t size,
    const char* func);

#endif /* _MYST_BACKTRACE_H */
