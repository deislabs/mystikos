#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct _FTS FTS;
typedef struct _FTSENT FTSENT;

int fts_close(FTS* ftsp)
{
    fprintf(stderr, "%s() unhandled\n", __FUNCTION__);
    abort();
    return 0;
}
