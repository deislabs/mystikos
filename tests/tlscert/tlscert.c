// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char* argv[])
{
    if (strcmp(getenv("MYST_TARGET"), "sgx") == 0)
    {
        char line[1024];
        FILE* fp = fopen("tmp/myst.key", "r");
        assert(fp != NULL);

        int linenum = 0;
        while (fgets(line, 1024, fp) != NULL)
        {
            puts(line);
            if (linenum == 0)
                assert(strstr(line, "BEGIN EC PRIVATE KEY"));
            linenum++;
        }
        fclose(fp);
        assert(linenum > 1);

        fp = fopen("tmp/myst.crt", "r");
        assert(fp != NULL);
        int foundOE = 0;
        while (fgets(line, 1024, fp) != NULL)
        {
            if (strstr(line, "MYSTIKOS"))
                foundOE = 1;
        }
        fclose(fp);
        assert(foundOE != 0);
    }

    return 0;
}
