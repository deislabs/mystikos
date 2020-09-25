#ifndef _LIBOS_STRINGS_H
#define _LIBOS_STRINGS_H

#include <libos/defs.h>
#include <libos/types.h>

#define LIBOS_STRLCPY(DEST, SRC) libos_strlcpy(DEST, SRC, sizeof(DEST))
#define LIBOS_STRLCAT(DEST, SRC) libos_strlcat(DEST, SRC, sizeof(DEST))

size_t libos_strlcpy(char* dest, const char* src, size_t size);

size_t libos_strlcat(char* dest, const char* src, size_t size);

int libos_strsplit(
    const char* str,
    const char* delim,
    char*** toks,
    size_t* ntoks);

int libos_strjoin(
    const char* toks[],
    size_t ntoks,
    const char* ldelim,
    const char* delim,
    const char* rdelim,
    char** str_out);

size_t libos_tokslen(const char* toks[]);

void libos_toks_dump(const char* toks[]);

/* remove count bytes from data starting at pos (return new size) */
ssize_t libos_memremove(void* data, size_t n, size_t pos, size_t count);

ssize_t libos_memremove_u64(void* data, size_t size, size_t pos, size_t count);

#endif /* _LIBOS_STRINGS_H */
