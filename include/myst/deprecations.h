// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_DEPRECATIONS_H
#define _MYST_DEPRECATIONS_H

/* These functions are deprecated for the Mystikos project */

__attribute__((__deprecated__)) char* strcpy(char* dest, const char* src);

__attribute__((__deprecated__)) int sprintf(char* str, const char* format, ...);

#endif /* _MYST_DEPRECATIONS_H */
