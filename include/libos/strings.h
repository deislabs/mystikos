#ifndef _LIBOS_STRINGS_H
#define _LIBOS_STRINGS_H

#include <libos/types.h>
#include <libos/defs.h>
#include <stdarg.h>
#include <unistd.h>

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

void* libos_memset(void* s, int c, size_t n);

void* libos_memcpy(void* dest, const void* src, size_t n);

int libos_memcmp(const void* s1, const void* s2, size_t n);

void* libos_memmove(void* dest_, const void* src_, size_t n);

size_t libos_strlen(const char* s);

int libos_strcmp(const char* s1, const char* s2);

int libos_strncmp(const char* s1, const char* s2, size_t n);

char* libos_strchr(const char* s, int c);

char* libos_strrchr(const char* s, int c);

char* libos_strdup(const char* s);

size_t libos_strspn(const char* s, const char* accept);

size_t libos_strcspn(const char* s, const char* reject);

char* libos_strtok_r(char* str, const char* delim, char** saveptr);

int libos_vsnprintf(char* str, size_t size, const char* format, va_list ap);

LIBOS_PRINTF_FORMAT(3, 4)
int libos_snprintf(char* str, size_t size, const char* format, ...);

LIBOS_PRINTF_FORMAT(2, 3)
int libos_console_printf(int fd, const char* format, ...);

int libos_console_vprintf(int fd, const char* format, va_list ap);

int libos_veprintf(const char* format, va_list ap);

int libos_vprintf(const char* format, va_list ap);

LIBOS_PRINTF_FORMAT(1, 2)
int libos_eprintf(const char* format, ...);

LIBOS_PRINTF_FORMAT(1, 2)
int libos_printf(const char* format, ...);

char* libos_strncpy(char* dest, const char* src, size_t n);

#endif /* _LIBOS_STRINGS_H */
