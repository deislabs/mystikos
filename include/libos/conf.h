#ifndef _LIBOS_CONF_H
#define _LIBOS_CONF_H

#include <stddef.h>

typedef struct libos_conf_err
{
    char buf[256];
} libos_conf_err_t;

typedef int (*libos_conf_callback_t)(
    const char* name,
    const char* value,
    void* callback_data,
    libos_conf_err_t* err);

int libos_conf_parse(
    const char* text,
    size_t text_size,
    libos_conf_callback_t callback,
    void* callback_data,
    size_t* error_line,
    libos_conf_err_t* err);

#endif /* _LIBOS_CONF_H */
