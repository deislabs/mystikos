// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_PROXYPIPEDEV_H
#define _MYST_PROXYPIPEDEV_H

#include <myst/pipedev.h>

int myst_proxypipe_wrap(uint64_t pipe_cookie, myst_pipe_t** pipe_out);

int myst_proxypipedev_wrap(
    uint64_t pipedev_cookie,
    myst_pipedev_t** pipedev_out);

bool myst_is_proxypipedev(const myst_pipedev_t* pipedev);

#endif /* _MYST_PROXYPIPEDEV_H */
