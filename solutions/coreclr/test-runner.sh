#!/bin/bash

USAGE="$0 path-to-myst exec|exec-sgx|exec-linux ext2|cpio <test_list_file>"
#NPROCS=$(grep -c ^processor /proc/cpuinfo)
NPROCS=1
if [[ "$3" != "ext2" ]]; then
	if [[ "$3" != "cpio" ]]; then
		echo "Unsupported fs: $3"
		echo $USAGE
		exit 1
	fi
fi

if [[ "$#" == 4 ]]; then
	mapfile -t TEST_LIST < $4
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
	for test in ${chunk[*]}
	do
		./run-single-test.sh $1 $2 $3 $test &
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

# Print pass/fail statistics
pass_count=0
if [[ -f PASSED ]]; then
	pass_count=$(wc -l PASSED | awk '{ print $1 }')
	echo "Tests passed: $pass_count"
	echo "Pass percentage: $(( $pass_count*100/$NUM_TESTS )) %"
	cat PASSED
fi

if [[ -f FAILED-139 ]]; then
	echo "****************************************"
	echo "Seg fault count: $(wc -l FAILED-139)"
	cat FAILED-139
fi

if [[ -f FAILED-134 ]]; then
	echo "****************************************"
	echo "Program abort count: $(wc -l FAILED-134)"
	cat FAILED-134
fi

if [[ -f FAILED-137 ]]; then
	echo "****************************************"
	echo "Timed out and Killed count: $(wc -l FAILED-137)"
	cat FAILED-137
fi

if [[ -f FAILED-1 ]]; then
	echo "****************************************"
	echo "General error count: $(wc -l FAILED-1)"
	cat FAILED-1
fi