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
  OUTPUT=$(2>&1 timeout 3 make one TEST=$test FS=$FS )
  echo $OUTPUT >> temp_$FILE.output
  HAS_UNHANDLED_SYSCALL=$(2>&1 timeout 3 make one TEST=$test FS=$FS | grep "unhandled")
  if [ -z "$HAS_UNHANDLED_SYSCALL" ]
  then
    # No unhandled syscall
    PASSED=$(echo "$OUTPUT" | grep TPASS) 
    FAILED=$(echo "$OUTPUT" | grep TFAIL)
    BROKEN=$(echo "$OUTPUT" | grep TBROK)
    FAIL_ENCLAVE=$(echo "$OUTPUT" | grep Error)
    TIMED_OUT=$(echo "$OUTPUT" | grep -F '[one] Terminated')
    if [[ $PASSED && -z $FAILED && -z $BROKEN && -z $FAIL_ENCLAVE && -z $TIMED_OUT ]]  
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

FS="$FS"_fs
awk '!seen[$9]++' temp_unhandled_syscalls.output | awk '{print $9}' | sort > unhandled_syscalls.txt
cat temp_unhandled_syscalls.output > "$FS"_tests_unhandled_syscalls.txt
sort temp_other_errors.output | awk '!seen[$0]++' > "$FS"_tests_other_errors.txt
cat temp_passed.output > "$FS"_tests_passed.txt

}

function show_stats() {
  echo "FILESYSTEM PASSED UNHANDLED_SYSCALLS OTHER_ERRORS"
  FS=ext2fs
  FS="$FS"_fs
  echo "$FS $(cat "$FS"_tests_passed.txt | wc -l) $(cat "$FS"_tests_unhandled_syscalls.txt | wc -l) $(cat "$FS"_tests_other_errors.txt | wc -l) "
  FS=hostfs
  FS="$FS"_fs
  echo "$FS $(cat "$FS"_tests_passed.txt | wc -l) $(cat "$FS"_tests_unhandled_syscalls.txt | wc -l) $(cat "$FS"_tests_other_errors.txt | wc -l) "
  FS=ramfs
  FS="$FS"_fs
  echo "$FS $(cat "$FS"_tests_passed.txt | wc -l) $(cat "$FS"_tests_unhandled_syscalls.txt | wc -l) $(cat "$FS"_tests_other_errors.txt | wc -l) "
}

FS=ext2fs
run_tests fstests

FS=hostfs
run_tests fstests

FS=ramfs
run_tests fstests

show_stats