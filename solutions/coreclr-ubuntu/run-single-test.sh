#!/bin/bash

USAGE="$0 path-to-myst null|exec-sgx|exec-linux config.json timeout ext2|cpio|package <path-to-test-dll>"
ret_val=-1
t0=$(date +"%s")
TIMEOUT=$4

if [[ "$5" == "package" ]]; then
    timeout --kill-after="${TIMEOUT}s" --signal=KILL $TIMEOUT \
        $1 \
        /coreclr-tests-all/$6 \
        --rootfs=ext2fs > /dev/null 2>&1
elif [[ "$5" == "ext2" ]]; then
    timeout --kill-after="${TIMEOUT}s" --signal=KILL $TIMEOUT \
        $1 $2 ext2fs \
        --app-config-path=$3 \
        /coreclr-tests-all/Tests/Core_Root/corerun \
        /coreclr-tests-all/$6 > /dev/null 2>&1
elif [[ "$5" == "cpio" ]]; then
    timeout --kill-after="${TIMEOUT}s" --signal=KILL $TIMEOUT \
        $1 $2 rootfs \
        --app-config-path=$3 \
        /coreclr-tests-all/Tests/Core_Root/corerun \
        /coreclr-tests-all/$6 > /dev/null 2>&1
else
    echo "$5 is not a supported fs."
    echo $USAGE
    exit 1
fi

ret_val=$?
t1=$(date +"%s")
echo "Test: $6 Exit code: $ret_val time taken: $(( $t1 - $t0 )) secs."

# Error code 100 represents success in dotnet runtime tests
if [[ $ret_val == 100 ]]
then
    echo $6 >> PASSED
else
    echo $6 >> FAILED-$ret_val
fi


