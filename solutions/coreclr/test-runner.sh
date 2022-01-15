#!/bin/bash

USAGE="$0 path-to-myst null|exec-sgx|exec-linux config.json timeout <test_list_file>"
NPROCS=$(grep -c ^processor /proc/cpuinfo)
NPROCS=2

if [[ "$#" == 5 ]]; then
	mapfile -t TEST_LIST < $5
else
	mapfile -t TEST_LIST < pr0-PASSED
fi

if [[ "$3" == "config_4g.json" ]]; then
	NPROCS=1
fi

NUM_TESTS=${#TEST_LIST[@]}
echo "Running $NUM_TESTS tests with parallelism: $NPROCS"
start_time=$(date +"%s")
for((i=0; i < $NUM_TESTS; ))
do
	echo "****************************************"
	for j in $(eval echo "{1..$NPROCS}")
	do
		test=${TEST_LIST[i]}
		echo "Run test $i $test"
		i=$((i+1))
		./run-single-test.sh $1 $2 $3 $4 $test &
	done
	wait
done
sudo rm -rf /tmp/myst*
end_time=$(date +"%s")
elapsed_secs=$(( end_time - start_time ))
echo "****************************************"
echo "Time elapsed $elapsed_secs seconds"
