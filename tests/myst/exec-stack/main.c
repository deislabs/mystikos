// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

void foo(void (*fn)())
{
    fn(); // this will fail if application stack is not executable
}
int main()
{
    void bar()
    {
    } // this will create a trampoline
    foo(bar);
    return 0;
}
