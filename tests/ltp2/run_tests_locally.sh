# this file is a test runner for tests. Segregates the syscall failures from the normal failures. 
# added option to see if the test passes 
# Add this to the Makefile: 
# ifdef TEST
# one:
# 	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs $(TEST)
# endif
# run using: make one TEST=/test/location

# rm *.output

function run_tests() {
FILE=$1

while read test; do
  echo "$test"
  OUTPUT=$(2>&1 make one TEST=$test FS=$FS )
  echo $OUTPUT >> temp_$FILE.output
  HAS_UNHANDLED_SYSCALL=$(2>&1 make one TEST=$test FS=$FS | grep "unhandled")
  if [ -z "$HAS_UNHANDLED_SYSCALL" ]
  then
    # No unhandled syscall
    PASSED=$(echo "$OUTPUT" | grep TPASS) 
    FAILED=$(echo "$OUTPUT" | grep TFAIL)
    BROKEN=$(echo "$OUTPUT" | grep TBROK)
    FAIL_ENCLAVE=$(echo "$OUTPUT" | grep Error)
    if [[ $PASSED && -z $FAILED && -z $BROKEN && -z $FAIL_ENCLAVE ]]  
    then
      echo $test >> temp_passed.output
    else
      echo $test >> temp_other_errors.output
    fi
  else
    echo "$test: $HAS_UNHANDLED_SYSCALL" >> temp_unhandled_syscalls.output
  fi
done <$FILE

awk '!seen[$9]++' temp_unhandled_syscalls.output | awk '{print $9}' | sort > unhandled_syscalls.txt
cat temp_unhandled_syscalls.output > "$FS"_tests_unhandled_syscalls.txt
sort temp_other_errors.output | awk '!seen[$0]++' > "$FS"_tests_other_errors.txt
cat temp_passed.output > "$FS"_tests_passed.txt

}

if [[ -z $FS ]]
then
  FS=ext2fs
fi
run_tests "$FS"_tests_allrunning.txt

# grep -Fvx -f partial.list complete.list > remaining.list

# echo "ALLRUNNING PASSED HANGING UNHANDLED_SYSCALLS OTHER_ERRORS"
# FS=ext2fs
# echo "$FS $(cat "$FS"_tests_allrunning.txt | wc -l) $(cat "$FS"_tests_passed.txt | wc -l)  $(cat "$FS"_tests_hanging.txt | wc -l) $(cat "$FS"_tests_unhandled_syscalls.txt | wc -l) $(cat "$FS"_tests_other_errors.txt | wc -l) "
# FS=hostfs
# echo "$FS $(cat "$FS"_tests_allrunning.txt | wc -l) $(cat "$FS"_tests_passed.txt | wc -l)  $(cat "$FS"_tests_hanging.txt | wc -l) $(cat "$FS"_tests_unhandled_syscalls.txt | wc -l) $(cat "$FS"_tests_other_errors.txt | wc -l) "
# FS=ramfs
# echo "$FS $(cat "$FS"_tests_allrunning.txt | wc -l) $(cat "$FS"_tests_passed.txt | wc -l)  $(cat "$FS"_tests_hanging.txt | wc -l) $(cat "$FS"_tests_unhandled_syscalls.txt | wc -l) $(cat "$FS"_tests_other_errors.txt | wc -l) "