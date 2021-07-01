#!/bin/bash
# this file is a test runner for tests. Segregates the syscall failures from the normal failures. 
# added option to see if the test passes 
# Add this to the Makefile: 
# ifdef TEST
# one:
# 	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs $(TEST)
# endif
# run using: make one TEST=/test/location

function run_tests() {

rm *.output

FILE=$1

while read test; do
  echo "$test"
  OUTPUT=$(2>&1 timeout 10 make one TEST=$test )
  RETURN_VAL=$?
  echo $OUTPUT >> temp_$FILE.output
  if [[ "$RETURN_VAL" -eq "0" ]]
  then
    FAILED=$(echo "$OUTPUT" | grep "unhandled")
    if [ -z "$FAILED" ]
    then
      echo $test >> temp_passed.output
    else
      SYSCALL=$(echo $OUTPUT | grep -o 'SYS_[a-z]\+')
      echo "$test: $SYSCALL" >> temp_unhandled_syscalls.output
    fi
  else
    echo $test >> temp_failed.output
  fi
  sudo rm -rf /tmp/myst*
done <$FILE

sort temp_failed.output | awk '!seen[$0]++' > tests_failed_$FILE.txt
cat temp_passed.output > tests_passed_$FILE.txt
cat temp_unhandled_syscalls.output > tests_unhandled_syscalls_$FILE.txt
}

function show_stats() {
  echo "PASSED FAILED"
  echo "$(cat tests_passed_$FILE.txt | wc -l) $(cat tests_failed_$FILE.txt | wc -l) "
}

function test_passed() {

  fs=$1
  test=$2
  if [[ ! -z $(cat tests_passed.txt | grep $test ) ]]
  then
    return 1
  else
    return 0
  fi

}

TESTS=tests.all
run_tests $TESTS

show_stats $TESTS

