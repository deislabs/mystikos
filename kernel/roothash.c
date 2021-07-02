#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <myst/cpio.h>
#include <myst/eraise.h>
#include <myst/hex.h>
#include <myst/roothash.h>
#include <myst/sha256.h>

int myst_roothash_verify(
    const void* roothashes_data,
    size_t roothashes_size,
    const uint8_t* root_hash,
    size_t root_hash_size)
{
    int ret = 0;

    if (!roothashes_data || !root_hash)
        ERAISE(-EINVAL);

    /* the roothashes file size must be a multiple of the SHA-256 size */
    if (roothashes_size % MYST_SHA256_SIZE)
        ERAISE(-EINVAL);

    /* only SHA-256 is supported */
    if (root_hash_size != MYST_SHA256_SIZE)
        ERAISE(-EINVAL);

    /* attempt to find a SHA-256 that matches the parameter */
    {
        const myst_sha256_t* p = (const myst_sha256_t*)roothashes_data;
        size_t n = roothashes_size / MYST_SHA256_SIZE;

        for (size_t i = 0; i < n; i++, p++)
        {
            if (memcmp(p, root_hash, MYST_SHA256_SIZE) == 0)
                goto done;
        }
    }

    /* not found */
    ret = -EACCES;

done:

    return ret;
}
