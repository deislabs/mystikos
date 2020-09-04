#include <libos/file.h>
#include <libos/types.h>
#include <libos/eraise.h>
#include <libos/malloc.h>
#include <libos/strings.h>

int libos_load_file(const char* path, void** data_out, size_t* size_out)
{
    int ret = 0;
    ssize_t n;
    struct stat st;
    char block[512];
    int fd = -1;
    void* data = NULL;
    uint8_t* p;

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    if (!path || !data_out || !size_out)
        ERAISE(-EINVAL);

    if ((fd = libos_open(path, O_RDONLY, 0)) < 0)
        ERAISE(-ENOENT);

    if (libos_fstat(fd, &st) != 0)
        ERAISE(-EINVAL);

    /* Allocate an extra byte for null termination */
    if (!(data = libos_malloc((size_t)(st.st_size + 1))))
        ERAISE(-ENOMEM);

    p = data;

    /* Null-terminate the data */
    p[st.st_size] = '\0';

    while ((n = libos_read(fd, block, sizeof(block))) > 0)
    {
        libos_memcpy(p, block, (size_t)n);
        p += n;
    }

    *data_out = data;
    data = NULL;
    *size_out = (size_t)st.st_size;

done:

    if (fd >= 0)
        libos_close(fd);

    if (data)
        libos_free(data);

    return ret;
}
