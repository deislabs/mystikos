#include <libos/tcall.h>

static libos_tcall_t _tcall;

long libos_tcall(long n, long params[6])
{
    return (*_tcall)(n, params);
}

void libos_enter_kernel(libos_tcall_t tcall)
{
    _tcall = tcall;
}
