// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_BACKTRACE_H
#define _MYST_BACKTRACE_H

#include <stddef.h>

size_t myst_backtrace(void** buffer, size_t size);

void myst_dump_backtrace(void** buffer, size_t size);

#endif /* _MYST_BACKTRACE_H */
