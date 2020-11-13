// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_TIME_H
#define _LIBOS_TIME_H

#include <stdint.h>
#include <time.h>

long libos_syscall_nanosleep(const struct timespec* req, struct timespec* rem);

void libos_sleep_msec(uint64_t milliseconds);

#endif /* _LIBOS_TIME_H */
