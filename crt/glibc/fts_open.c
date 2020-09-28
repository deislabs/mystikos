#include <assert.h>
#include <stdlib.h>

typedef struct _FTS FTS;
typedef struct _FTSENT FTSENT;

FTS* fts_open(
    char* const* path_argv,
    int options,
    int (*compar)(const FTSENT**, const FTSENT**))
{
    assert("unhandled" == NULL);
    abort();
    return NULL;
}
