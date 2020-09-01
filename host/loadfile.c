#include <libos/file.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

#if 0
int libos_load_file(const char* path, void** data_out, size_t* size_out)
{
    int ret = -1;
    FILE* is = NULL;
    void* data = NULL;
    size_t size;

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    /* Check parameters */
    if (!path || !data_out || !size_out)
        goto done;

    /* Get size of this file */
    {
        struct stat buf;

        if (stat(path, &buf) != 0)
            goto done;

        size = buf.st_size;
    }

    /* Allocate memory */
    if (!(data = malloc(size)))
        goto done;

    /* Open the file */
    if (!(is = fopen(path, "rb")))
        goto done;

    /* Read file into memory */
    if (fread(data, 1, size, is) != size)
        goto done;

    *size_out = size;
    *data_out = data;
    data = NULL;
    ret = 0;

done:

    if (data)
        free(data);

    if (is)
        fclose(is);

    return ret;
}
#endif
