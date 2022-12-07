#include <myst/debugmalloc.h>

size_t debug_malloc_check(bool print_allocations)
{
    if (print_allocations)
       return myst_debug_malloc_check();
    else
        return myst_memcheck();
}
