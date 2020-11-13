// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <libos/once.h>

int libos_once(libos_once_t* once, void (*func)(void))
{
    const uint64_t busy = 1;
    const uint64_t done = 2;

    if (!once || !func)
        return -EINVAL;

    libos_once_t status = __atomic_load_n(once, __ATOMIC_ACQUIRE);

    if (status != done)
    {
        libos_once_t expected = 0;

        bool ret = __atomic_compare_exchange_n(
            once, &expected, busy, false, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE);

        if (ret)
        {
            func();
            __atomic_store_n(once, done, __ATOMIC_RELEASE);
        }
        else
        {
            while (__atomic_load_n(once, __ATOMIC_ACQUIRE) != done)
                asm volatile("pause" ::: "memory");
        }
    }

    return 0;
}
