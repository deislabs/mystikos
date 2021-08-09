#include <stdio.h>

#include <myst/kstack.h>
#include <myst/spinlock.h>
#include <myst/stack.h>

typedef struct stack
{
    const void* stack;
    size_t size;
} stack_t;

// There is one entry stack, N kernel stacks, and N threads that may enter the
// kernel from the host, where N == MYST_MAX_KSTACKS.
#define MAX_STACKS (1 + MYST_MAX_KSTACKS + MYST_MAX_KSTACKS)

static stack_t _stacks[MAX_STACKS];
static size_t _nstacks;
static myst_spinlock_t _lock = MYST_SPINLOCK_INITIALIZER;

int myst_register_stack(const void* stack, size_t size)
{
    int ret = -EINVAL;

    myst_spin_lock(&_lock);
    {
        if (_nstacks < MAX_STACKS)
        {
            _stacks[_nstacks].stack = stack;
            _stacks[_nstacks].size = size;
            _nstacks++;
            ret = 0;
        }
    }
    myst_spin_unlock(&_lock);

    return ret;
}

int myst_unregister_stack(const void* stack, size_t size)
{
    int ret = -EINVAL;

    myst_spin_lock(&_lock);
    {
        for (size_t i = 0; i < _nstacks; i++)
        {
            if (_stacks[i].stack == stack && _stacks[i].size == size)
            {
                _stacks[i] = _stacks[--_nstacks];
                ret = 0;
                break;
            }
        }
    }
    myst_spin_unlock(&_lock);

    return ret;
}

bool myst_within_stack(const void* addr)
{
    bool within = false;

    myst_spin_lock(&_lock);
    {
        for (size_t i = 0; i < _nstacks; i++)
        {
            const uint8_t* lo = _stacks[i].stack;
            const uint8_t* hi = lo + _stacks[i].size;

            if ((const uint8_t*)addr >= lo && (const uint8_t*)addr < hi)
            {
                within = true;
                break;
            }
        }
    }
    myst_spin_unlock(&_lock);

    return within;
}
