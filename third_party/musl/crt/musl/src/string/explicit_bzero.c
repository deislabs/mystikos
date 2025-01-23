#define _BSD_SOURCE
#include <stdlib.h>
#include <string.h>

void explicit_bzero(void *d, size_t n)
{
	d = memset(d, 0, n);
	__asm__ __volatile__ ("" : : "r"(d) : "memory");
}

void __explicit_bzero_chk(void *d, size_t len, size_t dlen)
{
	if (dlen < len)
		abort();
	d = memset(d, 0, len);
	__asm__ __volatile__("" : : "r"(d) : "memory");
}