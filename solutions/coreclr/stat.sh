#!/bin/bash

function draw_double_line
{
	printf '=%.0s' {1..80}
	printf '\n'
}

# Print pass/fail statistics
NUM_TESTS=$(wc -l pr0-tests-all | awk '{ print $1 }')
pass_count=0
if [[ -f PASSED ]]; then
	pass_count=$(wc -l PASSED | awk '{ print $1 }')
	num_tests=pass_count
	echo "Tests passed: $pass_count/$NUM_TESTS"
	echo "Pass percentage: $(( $pass_count*100/$NUM_TESTS )) %"
	cat PASSED
fi
draw_double_line

for f in $(ls FAILED-*)
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

if [ "$(( pass_count*100/NUM_TESTS ))" -lt "99" ]; then
	echo "Failed to pass at least 99% - Pass percentage: $(( $pass_count*100/$NUM_TESTS ))%"
	exit 1
fi
