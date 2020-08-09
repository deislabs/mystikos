#include "posix_spinlock.h"

#include "posix_warnings.h"

/* Set the spinlock value to 1 and return the old value */
static unsigned int _spin_set_locked(posix_spinlock_t* spinlock)
{
    unsigned int value = 1;

    __asm__ volatile("lock xchg %0, %1;"
                 : "=r"(value)     /* %0 */
                 : "m"(*spinlock), /* %1 */
                   "0"(value)      /* also %2 */
                 : "memory");

    return value;
}

void posix_spin_lock(posix_spinlock_t* spinlock)
{
    if (spinlock)
    {
        while (_spin_set_locked((volatile unsigned int*)spinlock) != 0)
        {
            /* Spin while waiting for spinlock to be released (become 1) */
            while (*spinlock)
            {
                /* Yield to CPU */
                __asm__ volatile("pause");
            }
        }
    }
}

void posix_spin_unlock(posix_spinlock_t* spinlock)
{
    if (spinlock)
    {
        __asm__ volatile("movl %0, %1;"
            :
            : "r"(0), "m"(*spinlock) /* %1 */
            : "memory");
    }
}
