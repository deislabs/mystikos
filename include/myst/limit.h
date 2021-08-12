// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdlib.h>
#include <sys/resource.h>

#include <myst/defs.h>
#include <myst/types.h>

typedef struct myst_thread myst_thread_t;

int myst_limit_set_default(struct rlimit rlimits[]);

long myst_syscall_prlimit64(
    int pid,
    int resource,
    struct rlimit* new_rlim,
    struct rlimit* old_rlim);

int myst_limit_get_rlimit(pid_t pid, int resource, struct rlimit* rlim);

int myst_limit_set_rlimit(pid_t pid, int resource, struct rlimit* rlim);
