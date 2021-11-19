// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SYSLOG_H
#define _MYST_SYSLOG_H

#include <stdarg.h>
#include <syslog.h>

#include <myst/defs.h>

void __myst_vsyslog(
    const char* file,
    unsigned int line,
    const char* func,
    int priority,
    const char* format,
    va_list ap);

void myst_vsyslog(int priority, const char* format, va_list ap);

MYST_PRINTF_FORMAT(2, 3)
void myst_syslog(int priority, const char* format, ...);

MYST_PRINTF_FORMAT(5, 6)
void __myst_syslog(
    const char* file,
    unsigned int line,
    const char* func,
    int priority,
    const char* format,
    ...);

#define MYST_ELOG(FORMAT, ...) \
    __myst_syslog(             \
        __FILE__, __LINE__, __FUNCTION__, LOG_ERR, FORMAT, ##__VA_ARGS__)

#define MYST_WLOG(FORMAT, ...) \
    __myst_syslog(             \
        __FILE__, __LINE__, __FUNCTION__, LOG_WARNING, FORMAT, ##__VA_ARGS__)

#define MYST_ILOG(FORMAT, ...) \
    __myst_syslog(             \
        __FILE__, __LINE__, __FUNCTION__, LOG_INFO, FORMAT, ##__VA_ARGS__)

#define MYST_DLOG(FORMAT, ...) \
    __myst_syslog(             \
        __FILE__, __LINE__, __FUNCTION__, LOG_DEBUG, FORMAT, ##__VA_ARGS__)

#define MYST_SYSLOG(PRIORITY, FORMAT, ...) \
    __myst_syslog(                         \
        PRIORITY, FORMAT, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#endif /* _MYST_SYSLOG_H */
