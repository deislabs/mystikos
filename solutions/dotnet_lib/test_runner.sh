#!/usr/bin/env bash
# Use this script to run tests with different configuration

USAGE='Usage: test_runner.sh PLATFORM C_LIB RUNNER [TEST DLL]'

TESTCASES="testcases"
TESTCASE_PASS="${TESTCASES}/pass.txt"
TESTCASE_FAIL="${TESTCASES}/fail.txt"
TESTCASE_SKIP="${TESTCASES}/skip.txt"
TESTCASE_ALL="${TESTCASES}/all_test_dll.txt"

DOCKER_IMAGE=
DOCKER_IMAGE_GLIBC="hullcritical/dotnet-library-test:release-glibc"
DOCKER_IMAGE_MUSL="hullcritical/dotnet-library-test:release-musl"

DOCKERFILE=
DOCKERFILE_GLIBC_RUNNER="Dockerfile.glibc.runner"
DOCKERFILE_MUSL_RUNNER="Dockerfile.musl.runner"

CUSTOM_RUNNER="/runner/bin/Release/net5.0/runner"
DOTNET="/dotnet-lib-release/testhost/net5.0-Linux-Release-x64/dotnet"

run_single_test_mystikos() {
    PLATFORM=$1
    TEST_DLL=$2

    make run-single TARGET=$PLATFORM TEST_DLL=$TEST_DLL
}

run_single_test_docker() {
    NOT_USED=$1
    TEST_DLL=$2

    docker run -it $DOCKER_IMAGE $DOTNET test $TEST_DLL
}

run_all_test() {
    PLATFORM=$1
    RUNNER=$2
    TESTCASE=$TESTCASE_PASS

    if [[ $RUNNER == "custom" ]]; then
        if [[ $PLATFORM == "docker" ]]; then
            docker run -it $(docker build -q . -f ${DOCKERFILE}) $CUSTOM_RUNNER "/${TESTCASE}" /dotnet-lib-release/
        else
            make run-runner TARGET=$PLATFORM TESTCASE=$TESTCASE
        fi
    else
        run_test_method=
        if [[ $PLATFORM == "docker" ]]; then
            run_test_method=run_single_test_docker
        else
            run_test_method=run_single_test_mystikos
        fi

        mapfile -t CONTENT < $TESTCASE
        echo "# Found #${#CONTENT[@]} test DLLs"
        for each in "${CONTENT[@]}"; do
            $run_test_method $PLATFORM $each
        done
    fi
}

# Platform can be one of: docker, sgx, linux
PLATFORM=$1
# C lib can be one of: musl, glibc
CLIB=$2
# Runner can be one of: dotnet, custom
RUNNER=$3
# Optional argument: test DLL used, this argument will be ignored if runner is 'custom'
TEST_DLL=$4

if [[ -z $PLATFORM ]] || [[ -z $CLIB ]] || [[ -z $RUNNER ]]; then
    echo "Some of required argument is missing!"
    echo $USAGE
    exit 1
fi

if [[ $PLATFORM != "docker" ]] && [[ $PLATFORM != "sgx" ]] && [[ $PLATFORM != "linux" ]]; then
    echo "PLATFORM should be one of docker, sgx, linux"
    echo $USAGE
    exit 1
fi

if [[ $CLIB != "musl" ]] && [[ $CLIB != "glibc" ]]; then
    echo "CLIB should be one of musl, glibc"
    echo $USAGE
    exit 1
fi

if [[ $RUNNER != "dotnet" ]] && [[ $RUNNER != "custom" ]]; then
    echo "RUNNER should be one of dotnet, custom"
    echo $USAGE
    exit 1
fi

if [[ $CLIB == "musl" ]]; then
    DOCKER_IMAGE=$DOCKER_IMAGE_MUSL
    DOCKERFILE=$DOCKERFILE_MUSL_RUNNER
else
    DOCKER_IMAGE=$DOCKER_IMAGE_GLIBC
    DOCKERFILE=$DOCKERFILE_GLIBC_RUNNER
fi

if [[ -z $TEST_DLL ]] || [[ $RUNNER == "custom" ]]; then
    run_all_test $PLATFORM $RUNNER
else
    # Run a single test DLL

    if [[ $PLATFORM == "docker" ]]; then
        run_single_test_docker $PLATFORM $TEST_DLL
    else
        run_single_test_mystikos $PLATFORM $TEST_DLL
    fi
fi
