#include <stdio.h>

void foofoo()
{
}

int main(int argc, const char* argv[], const char* envp[])
{
    foofoo();
    
    printf("\n");
    
    for (int i = 0; i < argc; i++)
        printf("argv[%d]=%s\n", i, argv[i]);

    printf("\n");

    for (int i = 0; envp[i] != NULL; i++)
        printf("envp[%d]=%s\n", i, envp[i]);

    printf("\n");

    printf("=== Hello World!\n\n");

    return 0;
}
