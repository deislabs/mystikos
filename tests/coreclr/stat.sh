#!/bin/bash
function draw_double_line
{
	printf '=%.0s' {1..80}
	printf '\n'
}

USAGE="$0 <all-tests-file> <pass-percentage-threshold>"

ALL_TESTS_FILE=pr0-tests-all
if [[ $# -ge 1 ]]; then
    ALL_TESTS_FILE=$1
fi

PASS_PERCENT_THRESHOLD=99
if [[ $# -ge 2 ]]; then
    PASS_PERCENT_THRESHOLD=$2
fi

# Print pass/fail statistics
NUM_TESTS=$(wc -l ${PWD}/${ALL_TESTS_FILE} | awk '{ print $1 }')

draw_double_line
pass_count=0
if [[ -f PASSED ]]; then
	pass_count=$(wc -l ${PWD}/PASSED | awk '{ print $1 }')
	num_tests=pass_count
	echo "Tests passed: $pass_count/$NUM_TESTS"
	echo "Pass percentage: $(( $pass_count*100/$NUM_TESTS )) %"
	#cat PASSED
fi
draw_double_line

if ls ${PWD}/FAILED-* 1> /dev/null 2>&1 ; then
	for f in $(ls ${PWD}/FAILED-*) 
	do 
		wc -l $f
		cat $f
		draw_double_line
	done

	echo "Legend:"
	draw_double_line
	echo "Seg fault count (SIGSEGV) - FAILED-139"
	echo "Program abort (SIGABRT) - FAILED-134"
	echo "Timed out and Killed count - FAILED-137"
	draw_double_line
fi

if [ "$(( pass_count*100/NUM_TESTS ))" -lt "$PASS_PERCENT_THRESHOLD" ]; then
	echo "Failed to pass at least ${PASS_PERCENT_THRESHOLD}% - Pass percentage: $(( $pass_count*100/$NUM_TESTS ))% $pass_count/$NUM_TESTS"
	exit 1
fi