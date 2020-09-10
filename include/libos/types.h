#ifndef _LIBOS_TYPES_H
#define _LIBOS_TYPES_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#ifndef NULL
#define NULL ((void*)0)
#endif

#define LIBOS_PAGE_SIZE 4096

typedef long ssize_t;
typedef long off_t;
typedef unsigned long size_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int64_t;
typedef unsigned long uint64_t;
typedef unsigned long uintptr_t;
typedef long ptrdiff_t;
typedef long intptr_t;
typedef long time_t;
typedef long suseconds_t;

#ifndef __cplusplus
#define true 1
#define false 0
#define bool _Bool
#endif

typedef struct _libos_path
{
    char buf[PATH_MAX];
} libos_path_t;

#endif /* _LIBOS_TYPES_H */
