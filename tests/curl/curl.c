// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <curl/curl.h>
#include <assert.h>
#include <stdio.h>

int test_url(const char* url)
{
    CURL* curl;
    CURLcode res;
    int ret = -1;

    curl = curl_easy_init();

    if (!curl)
        goto done;

    assert(curl_easy_setopt(curl, CURLOPT_URL, url) == CURLE_OK);

    /* example.com is redirected, so we tell libcurl to follow redirection
     */
    assert(curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L) == CURLE_OK);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);

    /* Check for errors */
    if (res != CURLE_OK)
    {
        fprintf(
            stderr,
            "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
        ret = res;
        goto done;
    }

    ret = 0;

done:

    /* always cleanup */
    if (curl)
        curl_easy_cleanup(curl);
    return ret;
}

int main(int argc, const char* argv[])
{
    assert(argc == 2 && argv[1] != NULL);

    assert(test_url(argv[1]) == 0);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
