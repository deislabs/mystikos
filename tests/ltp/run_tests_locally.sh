# this file is a test runner for tests. Segregates the syscall failures from the normal failures. 
# added option to see if the test passes 
# Add this to the Makefile: 
# ifdef TEST
# one:
# 	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs $(TEST)
# endif
# run using: make one TEST=/test/location

rm *.output

function run_tests() {
FILE=$1

while read test; do
  echo "$test"
  OUTPUT=$(2>&1 make one TEST=$test)
  echo $OUTPUT >> temp_$FILE.output
  HAS_UNHANDLED_SYSCALL=$(2>&1 make one TEST=$test | grep "unhandled")
  if [ -z "$HAS_UNHANDLED_SYSCALL" ]
  then
    # No unhandled syscall
    PASSED=$(echo "$OUTPUT" | grep TPASS) 
    FAILED=$(echo "$OUTPUT" | grep TFAIL)
    BROKEN=$(echo "$OUTPUT" | grep TBROK)
    if [[ $PASSED && -z $FAILED && -z $BROKEN ]]  
    then
      echo $test >> temp_passed.output
    else
      echo $test >> temp_other_errors.output
    fi
  else
    echo "$test: $HAS_UNHANDLED_SYSCALL" >> temp_unhandled_syscalls.output
  fi
  echo "$test"
done <$FILE

awk '!seen[$9]++' temp_unhandled_syscalls.output | awk '{print $9}' | sort > unhandled_syscalls.txt
cat temp_unhandled_syscalls.output > tests_unhandled_syscalls.txt
sort temp_other_errors.output | awk '!seen[$0]++' > tests_other_errors.txt
cat temp_passed.output > tests_passed.txt

}

run_tests tests_allrunning.txt

# grep -Fvx -f partial.list complete.list > remaining.list