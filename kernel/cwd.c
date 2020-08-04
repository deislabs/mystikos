#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <libos/spinlock.h>
#include <libos/cwd.h>
#include <libos/strings.h>
#include "eraise.h"

static char _cwd[PATH_MAX] = "/";
static libos_spinlock_t _lock = LIBOS_SPINLOCK_INITIALIZER;

int libos_setcwd(const char* cwd)
{
    int ret = 0;
    bool locked = false;

    if (!cwd)
        ERAISE(-EINVAL);

    libos_spin_lock(&_lock);
    locked = true;

    if (LIBOS_STRLCPY(_cwd, cwd) >= sizeof(_cwd))
        ERAISE(-ERANGE);

done:

    if (locked)
        libos_spin_unlock(&_lock);

    return ret;
}

int libos_getcwd(libos_path_t* cwd)
{
    int ret = 0;
    bool locked = false;

    if (cwd)
        *cwd->buf = '\0';

    if (!cwd)
        ERAISE(-EINVAL);

    libos_spin_lock(&_lock);
    locked = true;

    if (LIBOS_STRLCPY(cwd->buf, _cwd) >= sizeof(cwd->buf))
        ERAISE(-ERANGE);

done:

    if (locked)
        libos_spin_unlock(&_lock);

    return ret;
}
