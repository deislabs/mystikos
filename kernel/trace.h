// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TRACE_H
#define _MYST_TRACE_H

#include <stdio.h>

#define TRACE printf("TRACE: %s(%u): %s\n", __FILE__, __LINE__, __FUNCTION__)

#endif /* _MYST_TRACE_H */
