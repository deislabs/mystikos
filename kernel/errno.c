#include <errno.h>

#include <libos/tcall.h>
#include <libos/thread.h>

int* __errno_location(void)
{
    int* ptr = NULL;

    libos_assume(libos_tcall_get_errno_location(&ptr) == 0);
    libos_assume(ptr != 0);

    return ptr;
}
