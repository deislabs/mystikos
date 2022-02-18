#!/bin/bash

USAGE="$0 path-to-myst null|exec-sgx|exec-linux "
USAGE="config.json timeout ext2|cpio|package "
USAGE="<test_list_file> <parallelism> <expected-exitcode>"
PARALLELISM=$(grep -c ^processor /proc/cpuinfo)

if [[ "$5" != "package" ]]; then
	if [[ "$5" != "ext2" ]]; then
		if [[ "$5" != "cpio" ]]; then
			echo "Unsupported mode: $5"
			echo $USAGE
			exit 1
		fi
	fi
fi

if [[ "$#" -ge 7 ]]; then
	PARALLELISM=$7
fi

TEST_LIST_FILE=${PWD}/pr0-PASSED
if [[ "$#" -ge 6 ]]; then
	TEST_LIST_FILE=$6
fi
mapfile -t TEST_LIST < $TEST_LIST_FILE

SCRIPT=`realpath -s $0`
SCRIPTPATH=`dirname $SCRIPT`

idx=1
NUM_TESTS=${#TEST_LIST[@]}
echo "Running $NUM_TESTS tests from $TEST_LIST_FILE."
echo "Parallelism: $PARALLELISM"
start_time=$(date +"%s")
for((i=0; i < ${#TEST_LIST[@]}; i+=PARALLELISM))
do
	echo "****************************************"
	echo "Run test $(( $i+1 )) - $(( $i+$PARALLELISM ))"
	chunk=( "${TEST_LIST[@]:i:PARALLELISM}" )
	for test in "${chunk[@]}"
	do
		${SCRIPTPATH}/run-single-test.sh $1 $2 $3 $4 $5 "$test" $8 &
	done
	wait
done
end_time=$(date +"%s")
elapsed_secs=$(( end_time - start_time ))
echo "****************************************"
echo "Time elapsed $elapsed_secs seconds ($TEST_LIST_FILE)"
