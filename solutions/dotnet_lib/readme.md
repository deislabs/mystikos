# dotnet library tests

This solution is used to run .Net library tests in Mystikos pipeline

## What's in this folder
1. runner/: stores the custom test runner, this is a better alternative to `dotnet test`
2. testcases/: stores path to dotnet library test DLLs
3. test_runner.sh: Runs test using `docker` or `dotnet test`

### testcases folder

`all_test_dll.txt`: all library test DLLs  
`all_testhost_dll.txt`: all testhost.dll we could find in dotnet library tests  
`pass.txt`: Tests that should pass when running in Mystikos  
`fail.txt`: Tests that currently fail when running in Mystikos  
`skip.txt`: Tests that should be skipped because they could crash Mystikos, or hangs forever, or don't contain unit tests  

## Docker images

Docker images are pre-built to save time, you can find repo here: https://hub.docker.com/repository/docker/hullcritical/dotnet-library-test

* hullcritical/dotnet-library-test:release-musl is built from Dockerfile.musl
* hullcritical/dotnet-library-test:release-glibc is built from Dockerfile.glibc

The main difference is whether dotnet is built by musl(on Alpine) or glibc(on Ubuntu)

There is another Dockerfile `Dockerfile.musl/glibc.runner`, this takes the pre-built image and append a custom test runner.

## Code snippets

Some random code snippets that might be useful

```bash
# Replace testhost.dll path to actual unit test DLL in testcases/all_testhost_dll.txt
# Before: ./Common.Tests/net5.0-Linux-Release/testhost.dll
# After: Common.Tests/net5.0-Linux-Release/Common.Tests.dll
function get_all_test_dll() {
    sed -e 's/^\.\/\(.*\.Tests\)\(.*\)\/testhost\.dll/\1\2\/\1\.dll/g' all_testhost_dll.txt 
}
```