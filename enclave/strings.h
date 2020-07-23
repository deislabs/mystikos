#ifndef _OEL_STRINGS_H
#define _OEL_STRINGS_H

#include "types.h"

size_t oel_strlen(const char* s);

size_t oel_strnlen(const char* s, size_t n);

int oel_strcmp(const char* s1, const char* s2);

int oel_strncmp(const char* s1, const char* s2, size_t n);

size_t oel_strlcpy(char* dest, const char* src, size_t size);

size_t oel_strlcat(char* dest, const char* src, size_t size);

void* oel_memcpy(void* dest, const void* src, size_t n);

void* oel_memset(void* s, int c, size_t n);

int oel_memcmp(const void* s1, const void* s2, size_t n);

void* oel_memmove(void* dest, const void* src, size_t n);

#endif /* _OEL_STRINGS_H */
