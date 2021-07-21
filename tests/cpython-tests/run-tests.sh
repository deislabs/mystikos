#!/bin/bash
TEST_FILE=tests.all
echo "${TEST_FILE}"
echo "$(wc -l ${TEST_FILE})"
idx=1
for tc in $(cat ${TEST_FILE});
do 
    #touch tmp.txt
    echo "Running ${tc} ${idx}"
    let "idx++"
    timeout --kill-after=1m --signal=KILL 60 make run-single TC=$tc
    # >> tmp.txt 2>&1 ;
    ret=$?
    echo "${ret}"
    echo "**************************************"
    if [[ "$ret" == "0" ]]; then
        echo "${tc}" >> tests.passed
    else
        echo "${tc}" >> tests.failed
        echo "${tc}" >> failed.${ret}
    fi
    # remove temp sockets created by python runtime
    rm @tmp_*
    #truncate --size 0 tmp.txt
done