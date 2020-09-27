#include <stdarg.h>
#include <syslog.h>

void __syslog_chk(int priority, int flag, const char* format, ...)
{
    va_list ap;

    va_start(ap, format);
    vsyslog(priority, format, ap);
    va_end(ap);
}
