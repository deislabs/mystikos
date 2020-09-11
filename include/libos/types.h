#ifndef _LIBOS_TYPES_H
#define _LIBOS_TYPES_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define LIBOS_PAGE_SIZE 4096

typedef struct _libos_path
{
    char buf[PATH_MAX];
} libos_path_t;

#endif /* _LIBOS_TYPES_H */
