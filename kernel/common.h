// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_COMMON_H
#define _LIBOS_COMMON_H

#include <stddef.h>
#include <stdarg.h>
#include <libos/malloc.h>
#include <libos/strings.h>

__attribute__((deprecated))
void* malloc(size_t size);

__attribute__((deprecated))
void free(void *ptr);

__attribute__((deprecated))
void* calloc(size_t nmemb, size_t size);

__attribute__((deprecated))
void* realloc(void* ptr, size_t size);

__attribute__((deprecated))
void* memset(void* s, int c, size_t n);

__attribute__((deprecated))
void* memcpy(void* dest, const void* src, size_t n);

__attribute__((deprecated))
int memcmp(const void* s1, const void* s2, size_t n);

__attribute__((deprecated))
void* memmove(void* dest_, const void* src_, size_t n);

__attribute__((deprecated))
size_t strlen(const char* s);

__attribute__((deprecated))
int strcmp(const char* s1, const char* s2);

__attribute__((deprecated))
size_t strlcpy(char* dest, const char* src, size_t size);

__attribute__((deprecated))
size_t strlcat(char* dest, const char* src, size_t size);

__attribute__((deprecated))
char* strchr(const char* s, int c);

__attribute__((deprecated))
char* strrchr(const char* s, int c);

__attribute__((deprecated))
int vsnprintf(char* str, size_t size, const char* format, va_list ap);

__attribute__((deprecated))
int snprintf(char* str, size_t size, const char* format, ...);

__attribute__((deprecated))
int strncmp(const char* s1, const char* s2, size_t n);

#endif /* _LIBOS_COMMON_H */
