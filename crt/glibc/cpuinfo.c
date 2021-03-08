#include <sched.h>
#include <stdlib.h>

void __sched_cpufree (cpu_set_t *set)
{
    free (set);
}

cpu_set_t * __sched_cpualloc (size_t count)
{
    return malloc (__CPU_ALLOC_SIZE (count));
}