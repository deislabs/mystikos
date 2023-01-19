#include <myst/defs.h>
#include <myst/mmanutils.h>
#include <myst/backtrace.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stddef.h>

MYST_NOINLINE
size_t myst_backtrace_impl(void** start_frame, void** buffer, size_t size)
{
    void** frame = start_frame;
    size_t n = 0;
    const int prot = PROT_READ;

    while (n < size)
    {
        if (myst_maccess(frame, 1, PROT_READ) != 0 ||
            myst_maccess(frame[1], 1, PROT_READ) != 0)
        {
            break;
        }

        buffer[n++] = frame[1];
        frame = (void**)*frame;
    }

    return n;
}

size_t myst_backtrace(void** buffer, size_t size)
{
    return myst_backtrace_impl(__builtin_frame_address(0), buffer, size);
}

void myst_dump_backtrace(void** buffer, size_t size)
{
    size_t i;

    for (i = 0; i < size; i++)
    {
        /* ATTN: address symbol names not known */
        fprintf(stderr, "%p\n", buffer[i]);
    }
}
