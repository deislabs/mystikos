# this file is a test runner for tests. Segregates the syscall failures from the normal failures. 
# added option to see if the test passes 
# Add this to the Makefile: 
# ifdef TEST
# one:
# 	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs $(TEST)
# endif
# run using: make one TEST=/test/location

function run_tests() {
FILE=$1

rm *.output*

while read test; do
  echo "$test"
  OUTPUT=$(2>&1 make one TEST=$test)
  echo $OUTPUT >> op_$FILE.output
  HAS_UNHANDLED_SYSCALL=$(2>&1 make one TEST=$test | grep "unhandled")
  if [ -z "$HAS_UNHANDLED_SYSCALL" ]
  then
    # No unhandled syscall
    PASSED=$(echo "$OUTPUT" | grep failed)
    if [ -z "$PASSED" ]
    then
      echo $test >> op_passed.output
    else
      echo $test >> op_other_errors.output
    fi
  else
    echo "$test: $HAS_UNHANDLED_SYSCALL" >> op_unhandled_syscalls.output
  fi
  echo "$test"
done <$FILE

cat op_$FILE.output | grep "unhandled syscall:" > op_unhandled_syscalls.output.crosscheck

}

run_tests all.txt