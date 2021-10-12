#!/bin/bash

USAGE="$0 <path-to-myst> <null|exec-sgx|exec-linux> <config.json> <timeout>"
USAGE+=" <ext2|cpio|package> <test_list_file> <expected-exitcode>"
NPROCS=$(grep -c ^processor /proc/cpuinfo)

if [[ "$5" != "package" ]]; then
	if [[ "$5" != "ext2" ]]; then
		if [[ "$5" != "cpio" ]]; then
			echo "Unsupported mode: $5"
			echo $USAGE
			exit 1
		fi
	fi
fi

HEAP_3g="-3g-"
if [[ "$5" != "package" ]]; then
	if [[ $NPROCS -ge 4 ]]; then
		NPROCS=4
	fi
	if [[ "$3" == "config_8g.json" ]]; then
		NPROCS=1
	fi
fi

if [[ "$#" -ge 6 ]]; then
	mapfile -t TEST_LIST < $6
else
	mapfile -t TEST_LIST < pr0-PASSED
fi

idx=1
NUM_TESTS=${#TEST_LIST[@]}
echo "Running $NUM_TESTS tests."
echo "Parallelism: $NPROCS"
start_time=$(date +"%s")
for((i=0; i < ${#TEST_LIST[@]}; i+=NPROCS))
do
	echo "****************************************"
	echo "Run test $(( $i+1 )) - $(( $i+$NPROCS ))"
	chunk=( "${TEST_LIST[@]:i:NPROCS}" )
	for test in "${chunk[@]}"
	do
		./run-single-test.sh $1 $2 $3 $4 $5 "$test" $7 &
	done
	wait
	# if any test failed, mystikos wasn't able to clean
	# the tmp files, cleanup files
	sudo rm -rf /tmp/myst*
done
end_time=$(date +"%s")
elapsed_secs=$(( end_time - start_time ))
echo "****************************************"
echo "Time elapsed $elapsed_secs seconds"
