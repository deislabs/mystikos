#!/bin/bash

USAGE="$0 path-to-myst null|exec-sgx|exec-linux config.json timeout <path-to-test-dll> <optional-extra-params>"
ret_val=-1
t0=$(date +"%s")
TIMEOUT=$4

timeout --kill-after="${TIMEOUT}s" --signal=KILL $TIMEOUT \
        $1 $2 ext2fs \
        --app-config-path=$3 \
        /coreclr-tests-all/Tests/Core_Root/corerun \
        /coreclr-tests-all/${@:5}> /dev/null 2>&1

ret_val=$?
t1=$(date +"%s")
echo "Test: $5 Exit code: $ret_val time taken: $(( $t1 - $t0 )) secs."

# Error code 100 represents success in dotnet runtime tests
if [[ $ret_val == 100 ]]
then
    echo $5 >> PASSED
else
    echo $5 >> FAILED-$ret_val
fi


