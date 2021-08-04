#!/bin/bash

USAGE="$0 path-to-myst exec|exec-sgx|exec-linux ext2|cpio <path-to-test-dll>"
HEAP_SIZE="1G"
ret_val=-1
t0=$(date +"%s")
TIMEOUT=15

if [[ "$3" == "ext2" ]]; then
    timeout --kill-after="${TIMEOUT}s" --signal=KILL $TIMEOUT \
        $1 $2 ext2fs \
        --app-config-path=config.json \
        --roothash=roothash \
        /coreclr-tests-all/Tests/Core_Root/corerun \
        /coreclr-tests-all/$4 > /dev/null 2>&1
elif [[ "$3" == "cpio" ]]; then
    timeout --kill-after="${TIMEOUT}s" --signal=KILL $TIMEOUT \
        $1 $2 rootfs \
        --app-config-path=config.json \
        /coreclr-tests-all/Tests/Core_Root/corerun \
        /coreclr-tests-all/$4 > /dev/null 2>&1
else
    echo "$3 is not a supported fs."
    echo $USAGE
    exit 1
fi

ret_val=$?
t1=$(date +"%s")
echo "Test: $4 Exit code: $ret_val time taken: $(( $t1 - $t0 )) secs."

# Error code 100 represents success in dotnet runtime tests
if [[ $ret_val == 100 ]]
then
    echo $4 >> PASSED
else
    echo $4 >> FAILED-$ret_val
fi


