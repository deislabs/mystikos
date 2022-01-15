#!/bin/bash

# Print pass/fail statistics
NUM_TESTS=$(wc -l pr0-tests-all | awk '{ print $1 }')
pass_count=0
if [[ -f PASSED ]]; then
	pass_count=$(wc -l PASSED | awk '{ print $1 }')
	num_tests=pass_count
	echo "Tests passed: $pass_count"
	echo "Pass percentage: $(( $pass_count*100/$NUM_TESTS ))%"
	#cat PASSED
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

if [[ -f FAILED-* ]]; then
	echo "Failed to pass all dotnet runtime P0 tests"
	exit 1
fi
