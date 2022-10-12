#include <assert.h>
#include <dlfcn.h>
#include <myst/ssr.h>
#include <stdio.h>

#define MHSM_SERVER "https://accmhsm.managedhsm.azure.net"
#define MHSM_API_VERSION "7.3-preview"

int main(int argc, char** argv)
{
    int ret = -1;
    ReleasedSecret secret = {0};
    unsigned char secret_from_file[1024];
    FILE* file = NULL;
    unsigned actual_secret_len = 0;

    void* handle = dlopen("libmhsm_ssr.so", RTLD_NOW);
    assert(handle);

    /* Get all the function pointers */
    SSR_CLIENT_SET_VERBOSE_FN verbose_fn = (SSR_CLIENT_SET_VERBOSE_FN)dlsym(
        handle, SSR_CLIENT_SET_VERBOSE_FN_NAME);
    SSR_CLIENT_INIT_FN init_fn =
        (SSR_CLIENT_INIT_FN)dlsym(handle, SSR_CLIENT_INIT_FN_NAME);
    SSR_CLIENT_GET_SECRET_FN get_fn =
        (SSR_CLIENT_GET_SECRET_FN)dlsym(handle, SSR_CLIENT_GET_SECRET_FN_NAME);
    SSR_CLIENT_FREE_SECRET_FN free_fn = (SSR_CLIENT_FREE_SECRET_FN)dlsym(
        handle, SSR_CLIENT_FREE_SECRET_FN_NAME);
    SSR_CLIENT_TERMINATE_FN terminate_fn =
        (SSR_CLIENT_TERMINATE_FN)dlsym(handle, SSR_CLIENT_TERMINATE_FN_NAME);
    assert(
        init_fn && get_fn && free_fn && terminate_fn &&
        "The client lib doesn't implement required APIs");

    if ((ret = verbose_fn(0)) != 0)
    {
        printf("SSR client set verbose failed with error code %d\n", ret);
        return ret;
    }
    printf("ssr_client_set_verbose() successful\n");

    /* Initialiaze the client lib */
    if ((ret = init_fn()) != 0)
    {
        printf("SSR client initialization failed with error code %d\n", ret);
        return ret;
    }

    /* Get a secret from m-hsm */
    ret = get_fn(MHSM_SERVER, MHSM_API_VERSION, "MyCustomKeyGA", &secret);
    if (ret != 0)
    {
        printf("SSR client failed to get secret with error code %d\n", ret);
        goto done;
    }

    printf(
        "The secret we get is {ID: %s, category: %s, type: %s, length: %zu}\n",
        secret.id,
        secret.category,
        secret.type,
        secret.length);

    /* Compare with the secret we retrieved through config file via the runtime
     */
    file = fopen("/mykey", "rb");
    actual_secret_len =
        fread(secret_from_file, 1, sizeof(secret_from_file), file);
    assert(
        actual_secret_len == secret.length && "The two secrets doesn't match");
    for (size_t i = 0; i < secret.length; i++)
    {
        assert(
            secret.data[i] == secret_from_file[i] &&
            "The two secrets doesn't match");
    }

    ret = 0;
    printf("====== SSR passed =======\n");

done:
    free_fn(&secret);

    terminate_fn();

    return ret;
}
