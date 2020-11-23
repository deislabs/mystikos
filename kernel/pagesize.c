#include <limits.h>
#include <unistd.h>

int getpagesize(void)
{
    _Static_assert(PAGE_SIZE == 4096, "getpagesize()");
    return PAGE_SIZE;
}
