#!/bin/bash
TEST_FILE=tests.all
if [[ ("$#" -eq 1) && (-f $1) ]]; then
    TEST_FILE=$1
fi
echo "${TEST_FILE}"
echo "$(wc -l ${TEST_FILE})"
idx=1
for tc in $(cat ${TEST_FILE});
do 
    echo "Running ${tc} ${idx}"
    let "idx++"
    timeout --kill-after=1m --signal=KILL 60 make run-single TC=$tc
    ret=$?
    echo "${ret}"
    echo "**************************************"
    # Uncomment for regenerating test lists
    # if [[ "$ret" == "0" ]]; then
    #     echo "${tc}" >> tests.passed
    # else
    #     echo "${tc}" >> tests.failed
    #     echo "${tc}" >> failed.${ret}
    # fi
    # remove temp sockets created by python runtime
    rm @tmp_* 2>&1 >> /dev/null
done