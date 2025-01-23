#include <stdlib.h>
#include <errno.h>
#include "malloc_impl.h"

void *libc_memalign(size_t alignment, size_t size);

int libc_posix_memalign(void **res, size_t align, size_t len)
{
	if (align < sizeof(void *)) return EINVAL;
	void *mem = libc_memalign(align, len);
	if (!mem) return errno;
	*res = mem;
	return 0;
}

__attribute__((__weak__))
int posix_memalign(void **res, size_t align, size_t len)
{
    return libc_posix_memalign(res, align, len);
}
