#include <libos/tcall.h>
#include <libos/eraise.h>
#include <errno.h>
#include <openenclave/enclave.h>

static long _tcall_random(void* data, size_t size)
{
    long ret = 0;
    extern oe_result_t oe_random(void* data, size_t size);

    if (!data)
        ERAISE(-EINVAL);

    if (oe_random(data, size) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

static long _tcall_thread_self(void)
{
    extern uint64_t oe_thread_self(void);
    return (long)oe_thread_self();
}

long libos_tcall(long n, long params[6])
{
    long ret = 0;
    const long x1 = params[0];
    const long x2 = params[1];
    const long x3 = params[2];
    const long x4 = params[3];
    const long x5 = params[4];
    const long x6 = params[5];

    (void)x1;
    (void)x2;
    (void)x3;
    (void)x4;
    (void)x5;
    (void)x6;

    switch ((libos_tcall_number_t)n)
    {
        case LIBOS_TCALL_RANDOM:
        {
            return _tcall_random((void*)x1, (size_t)x2);
        }
        case LIBOS_TCALL_THREAD_SELF:
        {
            return _tcall_thread_self();
        }
        default:
        {
            ERAISE(-EINVAL);
        }
    }

done:
    return ret;
}
