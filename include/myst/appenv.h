// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_APPENV_H
#define _MYST_APPENV_H

#include <myst/kernel.h>

int myst_create_appenv(myst_kernel_args_t* args);

int myst_appenv_free(myst_kernel_args_t* args);

#endif /* _MYST_APPENV_H */
