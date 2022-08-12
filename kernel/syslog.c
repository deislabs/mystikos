#include <syslog.h>

#include <myst/kernel.h>
#include <myst/printf.h>
#include <myst/syslog.h>

#define COLOR_RED "\e[31m"
#define COLOR_YELLOW "\e[33m"
#define COLOR_GREEN "\e[32m"
#define COLOR_RESET "\e[0m"

void __myst_vsyslog(
    const char* file,
    unsigned int line,
    const char* func,
    int priority,
    const char* format,
    va_list ap)
{
    static const char* _names[8] = {
        "panic",  /* LOG_EMERG */
        "alert",  /* LOG_ALERT */
        "crit",   /* LOG_CRIT */
        "err",    /* LOG_ERR */
        "warn",   /* LOG_WARNING */
        "notice", /* LOG_NOTICE */
        "info",   /* LOG_INFO */
        "debug",  /* LOG_DEBUG */
    };
    const int pri = (priority & 7);
    const char* name = _names[pri];

    if (__myst_kernel_args.syslog_level < pri)
        return;

    switch (pri)
    {
        case LOG_EMERG:
        case LOG_ALERT:
        case LOG_CRIT:
        case LOG_ERR:
            myst_eprintf(COLOR_RED);
            break;
        case LOG_WARNING:
        case LOG_NOTICE:
            myst_eprintf(COLOR_YELLOW);
            break;
        case LOG_INFO:
        case LOG_DEBUG:
            myst_eprintf(COLOR_GREEN);
            break;
    }

    myst_eprintf("mystikos: %s: ", name);

    if (file && line && func)
        myst_eprintf("%s(%u): %s(): ", file, line, func);

    myst_veprintf(format, ap);

    myst_eprintf("\n");
    myst_eprintf(COLOR_RESET);
}

void myst_vsyslog(int priority, const char* format, va_list ap)
{
    __myst_vsyslog(NULL, 0, NULL, priority, format, ap);
}

void myst_syslog(int priority, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    myst_vsyslog(priority, format, ap);
    va_end(ap);
}

void __myst_syslog(
    const char* file,
    unsigned int line,
    const char* func,
    int priority,
    const char* format,
    ...)
{
    va_list ap;
    va_start(ap, format);
    __myst_vsyslog(file, line, func, priority, format, ap);
    va_end(ap);
}
