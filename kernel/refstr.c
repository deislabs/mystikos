#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <myst/atexit.h>
#include <myst/refstr.h>

myst_refstr_t* myst_refstr_dup(const char* s)
{
    myst_refstr_t* refstr;

    if (!s)
        return NULL;

    size_t len = strlen(s);

    if (!(refstr = malloc(sizeof(myst_refstr_t) + len + 1)))
        return NULL;

    refstr->count = 1;
    memcpy(refstr->data, s, len + 1);

    return refstr;
}

void myst_refstr_ref(myst_refstr_t* refstr)
{
    if (refstr)
    {
        refstr->count++;
    }
}

void myst_refstr_unref(myst_refstr_t* refstr)
{
    if (refstr)
    {
        /* assert on underflow */
        assert(refstr->count > 0);

        if (--refstr->count == 0)
        {
            free(refstr);
        }
    }
}
