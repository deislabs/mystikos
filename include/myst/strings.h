// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_STRINGS_H
#define _MYST_STRINGS_H

#include <myst/defs.h>
#include <myst/types.h>

#define MYST_STRLCPY(DEST, SRC) myst_strlcpy(DEST, SRC, sizeof(DEST))
#define MYST_STRLCAT(DEST, SRC) myst_strlcat(DEST, SRC, sizeof(DEST))

size_t myst_strlcpy(char* dest, const char* src, size_t size);

size_t myst_strlcat(char* dest, const char* src, size_t size);

int myst_strsplit(
    const char* str,
    const char* delim,
    char*** toks,
    size_t* ntoks);

int myst_strjoin(
    const char* toks[],
    size_t ntoks,
    const char* ldelim,
    const char* delim,
    const char* rdelim,
    char** str_out);

size_t myst_tokslen(const char* toks[]);

void myst_toks_dump(const char* toks[]);

/* remove count bytes from data starting at pos (return new size) */
ssize_t myst_memremove(void* data, size_t n, size_t pos, size_t count);

ssize_t myst_memremove_u64(void* data, size_t size, size_t pos, size_t count);

MYST_INLINE bool myst_isspace(char c)
{
    return c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' ||
           c == '\v';
}

MYST_INLINE int myst_tolower(int c)
{
    MYST_STATIC_ASSERT('A' + ' ' == 'a');
    MYST_STATIC_ASSERT('Z' + ' ' == 'z');
    return (c >= 'A' && c <= 'Z') ? (c + ' ') : c;
}

MYST_INLINE int myst_isdigit(int c)
{
    return c >= '0' && c <= '9';
}

MYST_INLINE int myst_isprint(int c)
{
    return c >= ' ' && c <= '~';
}

/* convert a whole string to an integer */
int myst_str2int(const char* s, int* x);

/* convert a whole string to a long */
int myst_str2long(const char* s, long* x);

// BSD memcchr() function: return a pointer to the first byte that is not
// equal to c or null if not found.
void* myst_memcchr(const void* b, int c, size_t len);

/* returns -ERANGE if overflow detected, otherwise 0 */
int myst_snprintf(char* str, size_t size, const char* format, ...);

unsigned long int myst_strtoul(const char* nptr, char** endptr, int base);

long int myst_strtol(const char* nptr, char** endptr, int base);

double myst_strtod(const char* nptr, char** endptr);

#endif /* _MYST_STRINGS_H */
