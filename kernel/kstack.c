#include <myst/kernel.h>
#include <myst/kstack.h>
#include <myst/spinlock.h>
#include <myst/time.h>

static int _initialized;
static myst_kstack_t* _head;
static myst_spinlock_t _lock;

void myst_init_kstacks(void)
{
    myst_spin_lock(&_lock);
    {
        if (_initialized == 0)
        {
            uint8_t* p = (uint8_t*)__myst_kernel_args.kernel_stacks_data;

            for (size_t i = 0; i < MYST_MAX_KSTACKS; i++)
            {
                myst_kstack_t* kstack = (myst_kstack_t*)p;
                kstack->u.next = _head;
                _head = kstack;

                p += MYST_KSTACK_SIZE;
            }

            _initialized = 1;
        }
    }
    myst_spin_unlock(&_lock);
}

myst_kstack_t* myst_get_kstack(void)
{
    myst_kstack_t* kstack;

    myst_spin_lock(&_lock);
    {
        if ((kstack = _head))
            _head = _head->u.next;
    }
    myst_spin_unlock(&_lock);

    return kstack;
}

void myst_put_kstack(myst_kstack_t* kstack)
{
    myst_spin_lock(&_lock);
    {
        kstack->u.next = _head;
        _head = kstack;
    }
    myst_spin_unlock(&_lock);
}
