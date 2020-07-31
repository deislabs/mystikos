#ifndef _LIBOS_STRINGS_H
#define _LIBOS_STRINGS_H

#include <string.h>

#define STRLCPY(DEST, SRC) strlcpy(DEST, SRC, sizeof(DEST))
#define STRLCAT(DEST, SRC) strlcat(DEST, SRC, sizeof(DEST))

#endif /* _LIBOS_STRINGS_H */
