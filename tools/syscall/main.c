#include <myst/syscall.h>
#include <string.h>

int main(int argc, const char* argv[])
{
    const myst_syscall_pair_t* pairs = myst_syscall_pairs();

    if (argc != 1 && argc != 2)
    {
        fprintf(stderr, "Usage: %s [num|name]\n", argv[0]);
        exit(1);
    }

    if (argc == 1)
    {
        for (size_t i = 0; pairs[i].name; i++)
        {
            const myst_syscall_pair_t* p = &pairs[i];
            printf("%s %u\n", p->name, p->num);
        }
    }
    else
    {
        char* end;
        unsigned long num = strtoul(argv[1], &end, 10);

        if (*end)
        {
            long num = myst_syscall_num(argv[1]);

            if (num < 0)
            {
                fprintf(stderr, "not found\n");
                return 1;
            }

            printf("%ld\n", num);
        }
        else
        {
            const char* name = myst_syscall_name(num);

            if (!name)
            {
                fprintf(stderr, "not found\n");
                return 1;
            }

            printf("%s\n", name);
        }
    }

    return 0;
}
