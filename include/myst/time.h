// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TIME_H
#define _MYST_TIME_H

#include <stdint.h>
#include <time.h>

long myst_syscall_nanosleep(const struct timespec* req, struct timespec* rem);

void myst_sleep_msec(uint64_t milliseconds);

#endif /* _MYST_TIME_H */
