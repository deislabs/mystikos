#include <unistd.h>
#include <stdio.h>
#include <errno.h>

size_t confstr(int name, char *buf, size_t len)
{
	const char *s = "";
	if (!name) {
		s = "/bin:/usr/bin";
	} else if (name == _CS_GNU_LIBC_VERSION) {
		s = "glibc 2.27";
	} else if ((name&~4U)!=1 && name-_CS_POSIX_V6_ILP32_OFF32_CFLAGS>33U) {
		errno = EINVAL;
		return 0;
	}
	// snprintf is overkill but avoid wasting code size to implement
	// this completely useless function and its truncation semantics
	return snprintf(buf, len, "%s", s) + 1;
}
