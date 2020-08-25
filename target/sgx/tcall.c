#include <libos/tcall.h>
#include <libos/eraise.h>
#include <sys/syscall.h>
#include <errno.h>
#include <openenclave/enclave.h>

long oe_syscall(
    long n,
    long x1,
    long x2,
    long x3,
    long x4,
    long x5,
    long x6);

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

    switch (n)
    {
        case LIBOS_TCALL_RANDOM:
        {
            return _tcall_random((void*)x1, (size_t)x2);
        }
        case LIBOS_TCALL_THREAD_SELF:
        {
            return _tcall_thread_self();
        }
        case SYS_read:
        case SYS_write:
        case SYS_close:
        case SYS_poll:
        case SYS_ioctl:
        case SYS_readv:
        case SYS_writev:
        case SYS_select:
        case SYS_nanosleep:
        case SYS_fcntl:
        case SYS_gettimeofday:
        case SYS_sethostname:
        case SYS_bind:
        case SYS_connect:
        case SYS_recvfrom:
        case SYS_sendfile:
        case SYS_socket:
        case SYS_accept:
        case SYS_sendto:
        case SYS_sendmsg:
        case SYS_recvmsg:
        case SYS_shutdown:
        case SYS_listen:
        case SYS_getsockname:
        case SYS_getpeername:
        case SYS_socketpair:
        case SYS_setsockopt:
        case SYS_getsockopt:
        {
            return oe_syscall(n, x1, x2, x3, x4, x5, x6);
        }
        default:
        {
            ERAISE(-EINVAL);
        }
    }

done:
    return ret;
}
