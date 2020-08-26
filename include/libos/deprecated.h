// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_DEPRECATED_H
#define _LIBOS_DEPRECATED_H

#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>

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

__attribute__((deprecated))
char* strdup(const char* s);

__attribute__((deprecated))
size_t strspn(const char* s, const char* accept);

__attribute__((deprecated))
size_t strcspn(const char* s, const char* reject);

__attribute__((deprecated))
char* strtok_r(char* str, const char* delim, char** saveptr);

__attribute__((deprecated))
int printf(const char* format, ...);

__attribute__((deprecated))
int fprintf(FILE* stream, const char* format, ...);

__attribute__((deprecated))
int vprintf(const char *format, va_list ap);

__attribute__((deprecated))
int vfprintf(FILE* stream, const char* format, va_list ap);

__attribute__((deprecated))
void* memalign(size_t alignment, size_t size);

__attribute__((deprecated))
char* strcpy(char* dest, const char* src);

__attribute__((deprecated))
char* strncpy(char* dest, const char* src, size_t n);

__attribute__((deprecated))
int* __errno_location(void);

#endif /* _LIBOS_DEPRECATED_H */
