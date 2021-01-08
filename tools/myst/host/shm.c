// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/shm.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static pthread_t _clock_thread;

static void* _host_clock_task(void* args)
{
    struct timespec tp, sleep_tp;
    struct clock_ctrl* ctrl = (struct clock_ctrl*)args;

    // Set up sleep interval
    sleep_tp.tv_sec = ctrl->interval / NANO_IN_SECOND;
    sleep_tp.tv_nsec = ctrl->interval % NANO_IN_SECOND;

    // Usually the "done" flag is set on another thread.
    // Use __ATOMIC_ACQUIRE to prevent reordering by compilers.
    while (__atomic_load_n(&ctrl->done, __ATOMIC_ACQUIRE) == 0)
    {
        nanosleep(&sleep_tp, NULL);
        clock_gettime(CLOCK_MONOTONIC, &tp);
        ctrl->now = tp.tv_sec * NANO_IN_SECOND + tp.tv_nsec;
    }
    return NULL;
}

int shm_create_clock(struct myst_shm* shm, unsigned long clock_tick)
{
    struct timespec tp;
    int res = -1;
    shm->clock = calloc(1, sizeof(struct clock_ctrl));
    if (shm->clock == NULL)
    {
        fprintf(stderr, "Out of memory\n");
        return res;
    }

    // How many nanoseconds between 2 clock ticks.
    shm->clock->interval = clock_tick;

    // Remeber the base real time.
    clock_gettime(CLOCK_REALTIME, &tp);
    shm->clock->realtime0 = tp.tv_sec * NANO_IN_SECOND + tp.tv_nsec;

    // Remeber the base monotonic time.
    clock_gettime(CLOCK_MONOTONIC, &tp);
    shm->clock->monotime0 = tp.tv_sec * NANO_IN_SECOND + tp.tv_nsec;
    shm->clock->now = shm->clock->monotime0;

    if (pthread_create(&_clock_thread, 0, _host_clock_task, (void*)shm->clock))
    {
        fprintf(stderr, "Failed to create host clock thread\n");
        free(shm->clock);
        return res;
    }
    return 0;
}

void shm_free_clock(struct myst_shm* shm)
{
    __atomic_thread_fence(__ATOMIC_RELEASE);
    shm->clock->done = 1;
    pthread_join(_clock_thread, 0);

    free(shm->clock);
}
