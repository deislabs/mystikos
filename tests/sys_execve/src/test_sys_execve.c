// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef void (*test_case_t)(void);

void expect(int expected, int actual, const char* msg)
{
    if (expected != actual)
        fprintf(stderr, ">>> Error: %s with errno: %d\n", msg, errno);
}

void test_absolute_path()
{
    printf("Running test_absolute_path\n");
    const char* filename = "/bin/echo";
    char* const argv[] = {filename, "test_absolute_path", 0};
    execve(filename, argv, NULL);
}

void test_relative_path_1()
{
    printf("Running test_relative_path_1\n");

    const char* filename = "./bin/echo";
    char* const argv[] = {filename, "test_relative_path_1", 0};
    execve(filename, argv, NULL);
}

void test_relative_path_2()
{
    printf("Running test_relative_path_2\n");

    if (chdir("/bin") != 0)
    {
        assert("Failed to change dir to /bin");
        return;
    }

    const char* filename = "./echo";
    char* const argv[] = {filename, "test_relative_path_2", 0};
    execve(filename, argv, NULL);
}

void test_relative_path_3()
{
    printf("Running test_relative_path_3\n");

    if (chdir("/bin") != 0)
    {
        assert("Failed to change dir to /bin");
        return;
    }

    const char* filename = "./../bin/echo";
    char* const argv[] = {filename, "test_relative_path_3", 0};
    execve(filename, argv, NULL);
}

// Test invalid filename
void test_relative_path_4()
{
    printf("Running test_relative_path_4\n");

    const char* filename = "./none/exist/relative/path";
    char* const argv[] = {filename, "test_relative_path_4", 0};
    int ret = execve(filename, argv, NULL);

    expect(-1, ret, "execve should return -1");
    expect(ENOENT, errno, "errno should be ENOENT");
    exit(0);
}

void test_relative_path_5()
{
    printf("Running test_relative_path_5\n");

    if (chdir("/bin") != 0)
    {
        assert("Failed to change dir to /bin");
        return;
    }

    const char* filename = "echo";
    char* const argv[] = {filename, "test_relative_path_5", 0};
    execve(filename, argv, NULL);
}

int main(int argc, char* argv[])
{
    if (argc == 1)
    {
        printf("Usage: test [index of test case (0 based)]\n\t"
               "For example, to run second test : ./test 1\n");
        return 0;
    }

    const int number_tests = 6;
    const test_case_t test_cases[] = {test_absolute_path,
                                      test_relative_path_1,
                                      test_relative_path_2,
                                      test_relative_path_3,
                                      test_relative_path_4,
                                      test_relative_path_5};

    int selection = atoi(argv[1]);
    if (selection >= number_tests)
    {
        fprintf(
            stderr,
            "Invalid selection %d. Number should be <%d\n",
            selection,
            number_tests);
        return 1;
    }

    (test_cases[selection])();

    assert(0 && "Should not reach here");
    return 1;
}
