#include <malloc.h>
#include "malloc_impl.h"
 
hidden void *(*const __realloc_dep)(void *, size_t) = realloc;

size_t libc_malloc_usable_size(void *p)
{
	return p ? CHUNK_SIZE(MEM_TO_CHUNK(p)) - OVERHEAD : 0;
}

__attribute__((__weak__))
size_t malloc_usable_size(void *p)
{
    return libc_malloc_usable_size(p);
}
