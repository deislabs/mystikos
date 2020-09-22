#include <limits.h>
#include <string.h>
#include <stdlib.h>

#include <libos/eraise.h>
#include <libos/file.h>
#include <libos/strings.h>
#include <libos/tcall.h>

long libos_tcall_export_file(const char* path, const void* data, size_t size)
{
    long ret = 0;
    const char* env;
    char root[PATH_MAX];
    char file[PATH_MAX];
    char dir[PATH_MAX];
    char* p;

    if (!path || (!data && size))
        ERAISE(-EINVAL);

    if ((env = getenv("LIBOS_EXPORT_RAMFS")))
    {
        struct stat buf;

        if (stat(env, &buf) != 0 || !S_ISDIR(buf.st_mode))
            ERAISE(-ENOTDIR);

        if (libos_strlcpy(root, env, sizeof(root)) >= sizeof(root))
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        if (!(getcwd(root, sizeof(root))))
            ERAISE(-errno);
    }

    if (snprintf(file, sizeof(file), "%s/ramfs/%s", root, path) >= sizeof(file))
        ERAISE(-ENAMETOOLONG);

    if (libos_strlcpy(dir, file, sizeof(dir)) >= sizeof(dir))
        ERAISE(-ENAMETOOLONG);

    /* Chop off the final component */
    if ((p = strrchr(dir, '/')))
        *p = '\0';
    else
        ERAISE(-EINVAL);

    ECHECK(libos_mkdirhier(dir, 0777));
    ECHECK(libos_write_file(file, data, size));

done:
    return ret;
}
