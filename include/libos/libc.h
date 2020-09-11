#ifndef _LIBOS_LIBC_H
#define _LIBOS_LIBC_H

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* libc function table that can be passed between ELF images */
typedef struct libc
{
    FILE* (*fopen)(const char*, const char*);

    FILE* (*fdopen)(int, const char*);

    size_t (*fread)(void*, size_t, size_t, FILE*);

    size_t (*fwrite)(const void*, size_t, size_t, FILE*);

    int (*fseek)(FILE*, long, int);

    long (*ftell)(FILE*);

    int (*fclose)(FILE*);

    void (*setbuf)(FILE*, char*);

    int (*open)(const char*, int, ...);

    int (*close)(int);

    int (*fcntl)(int, int, ...);

    char* (*getenv)(const char*);

    int* (*__errno_location)(void);

    pid_t (*getpid)(void);

    long int (*strtol)(const char*, char**, int);

    int (*access)(const char*, int);

    int (*mkdir)(const char*, mode_t);

    void (*abort)(void);

    int (*vfprintf)(FILE*, const char*, va_list);

    int (*atoi)(const char*);

    void* (*malloc)(size_t size);

    void (*free)(void* ptr);

    void* (*memset)(void* s, int c, size_t n);

    void* (*memcpy)(void* dest, const void* src, size_t n);

    char* (*strcpy)(char* dest, const char* src);

    size_t (*strlen)(const char* s);

} libc_t;

#endif /* _LIBOS_LIBC_H */
