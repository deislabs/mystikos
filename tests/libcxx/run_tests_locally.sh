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
  OUTPUT=$(2>&1 timeout 3 make one TEST=$test )
  echo $OUTPUT >> temp_$FILE.output
  HAS_UNHANDLED_SYSCALL=$(2>&1 timeout 3 make one TEST=$test | grep "unhandled")
  if [ -z "$HAS_UNHANDLED_SYSCALL" ]
  then
    # No unhandled syscall
    FAILED=$(echo "$OUTPUT" | grep failed)
    FAIL_ENCLAVE=$(echo "$OUTPUT" | grep OE_ENCLAVE_ABORTING)
    TIMED_OUT=$(echo "$OUTPUT" | grep -F '[one] Terminated')
    if [[ -z $FAILED && -z $FAIL_ENCLAVE && -z $TIMED_OUT ]]  
    then
      echo $test >> temp_passed.output
    else
      echo $test >> temp_other_errors.output
    fi
  else
    echo "$test: $HAS_UNHANDLED_SYSCALL" >> temp_unhandled_syscalls.output
  fi
  sudo rm -rf /tmp/myst*
done <$FILE

awk '!seen[$9]++' temp_unhandled_syscalls.output | awk '{print $9}' | sort >> unhandled_syscalls_$FILE.txt
cat temp_unhandled_syscalls.output >> tests_unhandled_syscalls_$FILE.txt
sort temp_other_errors.output | awk '!seen[$0]++' >> tests_other_errors_$FILE.txt
cat temp_passed.output >> tests_passed_$FILE.txt
}

function show_stats() {
  echo "PASSED UNHANDLED_SYSCALLS OTHER_ERRORS"
  echo "$FS $(cat tests_passed.txt | wc -l) $(cat tests_unhandled_syscalls.txt | wc -l) $(cat tests_other_errors.txt | wc -l) "
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

# TESTS=builttests_exe1.all
# run_tests $TESTS

# TESTS=builttests_exe2.all
# run_tests $TESTS

# TESTS=builttests_exe3.all
# run_tests $TESTS

TESTS=$1
run_tests $TESTS

show_stats

