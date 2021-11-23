#include <sys/mman.h>

#include <myst/kernel.h>
#include <myst/kstack.h>
#include <myst/mmanutils.h>
#include <myst/panic.h>
#include <myst/spinlock.h>
#include <myst/stack.h>
#include <myst/thread.h>
#include <myst/time.h>

static myst_kstack_t* _head;
static myst_spinlock_t _lock;

/* allocate a new kernel stack with a protected guard page */
static long _new_kstack(void* arg)
{
    myst_kstack_t* kstack;

    (void)arg;

    /* allocate the kernel stack space */
    {
        const size_t length = sizeof(myst_kstack_t);
        const int prot = PROT_READ | PROT_WRITE;
        const int flags = MAP_ANONYMOUS | MAP_PRIVATE;

        kstack = (myst_kstack_t*)myst_mmap(NULL, length, prot, flags, -1, 0);

        if ((long)kstack < 0)
            return (long)NULL;
    }

    /* protect the guard page */
    if (myst_mprotect(kstack->guard, PAGE_SIZE, PROT_NONE) != 0)
        return (long)NULL;

    return (long)kstack;
}

MYST_ALIGN(16)
static uint8_t _stack[4 * PAGE_SIZE];
static myst_spinlock_t _lock_stack;

myst_kstack_t* myst_get_kstack(void)
{
    myst_kstack_t* kstack = NULL;

    myst_spin_lock(&_lock);
    {
        if (_head)
        {
            /* use the first kstack on the list (likely case) */
            if ((kstack = _head))
                _head = _head->u.next;
        }
    }
    myst_spin_unlock(&_lock);

    if (kstack == NULL)
    {
        myst_spin_lock(&_lock_stack);

        /* allocate a new kstack (unlikely case) */
        uint8_t* sp = _stack + sizeof(_stack);
        kstack = (myst_kstack_t*)myst_call_on_stack(sp, _new_kstack, NULL);

        myst_spin_unlock(&_lock_stack);
    }

    myst_register_stack(kstack->u.__data, sizeof(kstack->u.__data));

    return kstack;
}

void myst_put_kstack(myst_kstack_t* kstack)
{
    myst_unregister_stack(kstack->u.__data, sizeof(kstack->u.__data));
    myst_spin_lock(&_lock);
    {
        kstack->u.next = _head;
        _head = kstack;
    }
    myst_spin_unlock(&_lock);
}
