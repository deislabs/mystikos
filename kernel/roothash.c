#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <myst/cpio.h>
#include <myst/eraise.h>
#include <myst/roothash.h>
#include <myst/sha256.h>
#include <myst/hex.h>

static bool _isspace(char c)
{
    switch (c)
    {
        case ' ':
        case '\f':
        case '\n':
        case '\r':
        case '\t':
        case '\v':
            return true;
        default:
            return false;
    }
}

int myst_roothash_verify(
    const void* cpio_data,
    size_t cpio_size,
    const uint8_t* root_hash,
    size_t root_hash_size)
{
    int ret = 0;
    size_t pos = 0;
    char* ascii = NULL;
    uint8_t* binary = NULL;
    size_t binary_size;

    if (!cpio_data || !cpio_size || !root_hash)
        ERAISE(-EINVAL);

    for (;;)
    {
        myst_cpio_entry_t ent;
        const void* file_data;
        int r;
        ssize_t n;

        if ((r = myst_cpio_next_entry(
                 cpio_data, cpio_size, &pos, &ent, &file_data)) == 0)
        {
            break;
        }

        if (r < 0)
            ERAISE(-EINVAL);

        if (S_ISDIR(ent.mode))
        {
            continue;
        }
        else if (S_ISLNK(ent.mode))
        {
            continue;
        }
        else if (S_ISREG(ent.mode))
        {
            if (strncmp(ent.name, "roothashes/", 7) == 0 && ent.size > 0)
            {
                if (!(ascii = malloc(ent.size + 1)))
                    ERAISE(-ENOMEM);

                memcpy(ascii, file_data, ent.size);
                ascii[ent.size] = '\0';

                /* remove trailing slashes */
                {
                    char* end = ascii + strlen(ascii);

                    while (end != ascii && _isspace(end[-1]))
                        *--end = '\0';
                }

                /* calculate the length of the hash */
                binary_size = strlen(ascii) / 2;

                if (root_hash_size != binary_size)
                    ERAISE(-EINVAL);

                /* allocate the hash buffer */
                if (!(binary = malloc(binary_size)))
                    ERAISE(-ENOMEM);

                /* convert to binary */
                ECHECK((n = myst_ascii_to_bin(ascii, binary, binary_size)));

                if (memcmp(binary, root_hash, binary_size) == 0)
                {
                    /* success */
                    goto done;
                }

                free(binary);
                binary = NULL;
                free(binary);
                binary = NULL;
            }
        }
    }

    ERAISE(-EPERM);

done:

    if (ascii)
        free(ascii);

    if (binary)
        free(binary);

    return ret;
}
