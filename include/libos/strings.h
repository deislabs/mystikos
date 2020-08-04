#ifndef _LIBOS_STRINGS_H
#define _LIBOS_STRINGS_H

#include <libos/types.h>

#define LIBOS_STRLCPY(DEST, SRC) libos_strlcpy(DEST, SRC, sizeof(DEST))
#define LIBOS_STRLCAT(DEST, SRC) libos_strlcat(DEST, SRC, sizeof(DEST))

size_t libos_strlcpy(char* dest, const char* src, size_t size);

size_t libos_strlcat(char* dest, const char* src, size_t size);

#endif /* _LIBOS_STRINGS_H */
