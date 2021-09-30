#ifndef SECURE_SECRET_RELEASE_H
#define SECURE_SECRET_RELEASE_H

#include <stddef.h>
#include <stdint.h>

#define SSR_CLIENT_SET_VERBOSE_FN_NAME "ssr_client_set_verbose"
#define SSR_CLIENT_INIT_FN_NAME "ssr_client_init"
#define SSR_CLIENT_GET_SECRET_FN_NAME "ssr_client_get_secret"
#define SSR_CLIENT_FREE_SECRET_FN_NAME "ssr_client_free_secret"
#define SSR_CLIENT_TERMINATE_FN_NAME "ssr_client_terminate"

typedef struct _releasedSecret
{
    uint32_t schemaVersion; /* schema version of this structure */
    char* id;               /* ID of the secret */
    char* category;         /* key/cert/etc. */
    char* type;             /* RSA/EC/AES/etc. */
    char* description;      /* optional desc. from the secret service */
    uint8_t* data;          /* the secret as a binary blob */
    size_t length;          /* the length of the blob */
} ReleasedSecret;

typedef int (*SSR_CLIENT_SET_VERBOSE_FN)(unsigned);
typedef int (*SSR_CLIENT_INIT_FN)(void);
typedef int (*SSR_CLIENT_GET_SECRET_FN)(
    const char*,
    const char*,
    const char*,
    ReleasedSecret*);
typedef void (*SSR_CLIENT_FREE_SECRET_FN)(ReleasedSecret*);
typedef void (*SSR_CLIENT_TERMINATE_FN)(void);

#ifdef __cplusplus
extern "C"
{
#endif

    int ssr_client_set_verbose(unsigned level);

    int ssr_client_init(void);

    int ssr_client_get_secret(
        const char* holder_url,
        const char* api_version,
        const char* id,
        ReleasedSecret* secret);

    void ssr_client_free_secret(ReleasedSecret* secret);

    void ssr_client_terminate(void);

#ifdef __cplusplus
}
#endif

#endif // SECURE_SECRET_RELEASE_H
