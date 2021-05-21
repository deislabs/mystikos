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

bool myst_isspace(char c);

/* convert a whole string to an integer */
int myst_str2int(const char* s, int* x);

void* myst_memcchr(const void* s, int c, size_t n);

void* myst_memcchr_u32(const void* s, uint32_t c, size_t n);

uint32_t* myst_memset_u32(uint32_t* s, uint32_t c, size_t n);

__uint128_t* myst_bzero_u128(__uint128_t* s, size_t n);

#endif /* _MYST_STRINGS_H */
