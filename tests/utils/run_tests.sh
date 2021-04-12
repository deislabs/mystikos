#!/bin/bash

##==============================================================================
##
## ./run_tests.sh <test_file> <increment> <test_command> ...
##
## Run tests from a test_file incrementally. The script passes the index and
## the increment as the last arguments of the test command.
##
##==============================================================================

if [ "$#" -lt "2" ]; then
    echo "Usage: $0 <test_file> <increment> <test_command...>"
    exit 1
fi

test_file=$1
shift

increment=$1
shift

test_command=$*

# check whether increment is an integer:
if [ ! "${increment}" -gt "0" ] 2> /dev/null
then
    echo "$0: invalid increment argument: ${increment}"
    exit 1
fi

# check whether test file exists:
if [ ! -f ${test_file} ]; then
    echo "$0: no such test file: ${test_file}"
    exit 1
fi

# get the number of lines in the test file:
num_lines=$(wc -l ${test_file} | cut -d " " -f 1)

# set the loop count to zero
index=0

# loop through the lines advancing increment lines at a time
while [ "${index}" -lt "${num_lines}" ]
do
    ${test_command} ${index} ${increment}
    if [ "$?" != "0" ]; then
        exit 1
    fi
    index=$((index+increment))
done
