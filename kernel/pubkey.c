#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <myst/cpio.h>
#include <myst/eraise.h>
#include <myst/pubkey.h>
#include <myst/tcall.h>

int myst_pubkey_verify(
    const void* cpio_data,
    size_t cpio_size,
    const uint8_t* hash,
    size_t hash_size,
    const uint8_t* signer,
    size_t signer_size,
    const uint8_t* signature,
    size_t signature_size)
{
    int ret = 0;
    size_t pos = 0;
    char* pubkey = NULL;

    if (!cpio_data || !cpio_size)
        ERAISE(-EINVAL);

    if (!hash || !hash_size)
        ERAISE(-EINVAL);

    if (!signer || !signer_size)
        ERAISE(-EINVAL);

    if (!signature || !signature_size)
        ERAISE(-EINVAL);

    for (;;)
    {
        myst_cpio_entry_t ent;
        const void* file_data;
        int r;

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
            if (strncmp(ent.name, "pubkeys/", 7) == 0 && ent.size > 0)
            {
                if (!(pubkey = malloc(ent.size + 1)))
                    ERAISE(-ENOMEM);

                memcpy(pubkey, file_data, ent.size);
                pubkey[ent.size] = '\0';

                if (myst_tcall_verify_signature(
                        pubkey,
                        hash,
                        hash_size,
                        signer,
                        signer_size,
                        signature,
                        signature_size) == 0)
                {
                    /* success! */
                    goto done;
                }

                free(pubkey);
                pubkey = NULL;
            }
        }
    }

    ret = -EPERM;

done:

    if (pubkey)
        free(pubkey);

    return ret;
}
