#include <stdio.h>
#include <string.h>

#include <myst/eraise.h>
#include <myst/fssig.h>

int myst_load_fssig(const char* path, myst_fssig_t* fssig)
{
    int ret = 0;
    FILE* os = NULL;
    ssize_t size = sizeof(myst_fssig_t);
    myst_fssig_t buf;

    if (fssig)
        memset(fssig, 0, sizeof (myst_fssig_t));

    if (!path || !fssig)
        ERAISE(-EINVAL);

    if (!(os = fopen(path, "rb")))
        ERAISE(-ENOENT);

    if (fseek(os, 0, SEEK_END) != 0)
        ERAISE(-ENOENT);

    if (fseek(os, -size, SEEK_END) != 0)
        ERAISE(-ENOENT);

    if (fread(&buf, 1, size, os) != size)
        ERAISE(-EIO);

    if (buf.magic != MYST_FSSIG_MAGIC)
        ERAISE(-ENOTSUP);

    memcpy(fssig, &buf, sizeof(myst_fssig_t));

done:

    if (os)
        fclose(os);

    return ret;
}
