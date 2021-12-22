# this file is a test runner for tests. Segregates the syscall failures from the normal failures. 
# added option to see if the test passes 
# Add this to the Makefile: 
# ifdef TEST
# one:
# 	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs $(TEST)
# endif
# run using: make one TEST=/test/location

function run_tests() {

  sudo rm temp_other_errors.output temp_passed.output temp_unhandled_syscalls.output "temp_$FS.output"

  FILE=$1

  echo "Starting run for FS= $FS TEST_FILE= $FILE"

  while read test; do
    echo -n "$test FS=$FS"
    if [ ! -v $(grep $test tests_flakey.txt | awk '{print $1}') ]
    then
      echo " SKIPPED: flakey"
      continue
    fi
    OUTPUT=$(2>&1 sudo timeout 1m make one TEST=$test FS=$FS )
    RETURN_VAL=$?
    echo "$OUTPUT" >> "temp_$FS.output"
    if [[ "$RETURN_VAL" -eq "0" ]]
    then
      # Passing test
      PASSED=$(echo "$OUTPUT" | grep TPASS) 
      FAILED=$(echo "$OUTPUT" | grep TFAIL) 
      if [[ $PASSED && -z $FAILED ]]  
      then
        echo $test >> temp_passed.output
        echo " PASSED"
      else
        echo $test >> temp_other_errors.output
        echo " FAILED"
      fi
    else
      HAS_UNHANDLED_SYSCALL=$(echo "$OUTPUT" | grep "unhandled")
      failing_syscall=${HAS_UNHANDLED_SYSCALL##*:} # retain the part after the last colon, i.e the syscall name
      if [[ $HAS_UNHANDLED_SYSCALL ]]
      then
        echo "$test: $failing_syscall" >> temp_unhandled_syscalls.output
        echo " UNHANDLED SYSCALL: $failing_syscall"
      else
        echo $test >> temp_other_errors.output
        echo " FAILED"
      fi
    fi
    sudo rm -rf /tmp/myst*
  done <$FILE

  awk '!seen[$2]++' temp_unhandled_syscalls.output | awk '{print $2}' | sort > unhandled_syscalls.txt
  sed 's/:.*:/:/' temp_unhandled_syscalls.output > "$FS"_tests_unhandled_syscalls.txt
  sort temp_other_errors.output | awk '!seen[$0]++' > "$FS"_tests_other_errors.txt
  cat temp_passed.output > "$FS"_tests_passed.txt

  grep -Fxf "$FS"_tests_passed.txt fstests > "$FS"_fs_tests_passed.txt
  
  echo "========================================================="
}

function show_stats() {
  echo "FILESYSTEM PASSED UNHANDLED_SYSCALLS OTHER_ERRORS"
  FS=ext2fs
  echo "$FS $(cat "$FS"_tests_passed.txt | wc -l) $(cat "$FS"_tests_unhandled_syscalls.txt | wc -l) $(cat "$FS"_tests_other_errors.txt | wc -l) "
  FS=hostfs
  echo "$FS $(cat "$FS"_tests_passed.txt | wc -l) $(cat "$FS"_tests_unhandled_syscalls.txt | wc -l) $(cat "$FS"_tests_other_errors.txt | wc -l) "
  FS=ramfs
  echo "$FS $(cat "$FS"_tests_passed.txt | wc -l) $(cat "$FS"_tests_unhandled_syscalls.txt | wc -l) $(cat "$FS"_tests_other_errors.txt | wc -l) "
}

function generate_matrix() {

  echo -e "## TEST MATRIX\n"
  echo -e "| TEST | EXT2FS | HOSTFS | RAMFS |"
  echo -e "| --- | --- | --- | --- |"

  while IFS= read -r TEST
  do
    test_passed ramfs $TEST
    RAMFS=$?
    test_passed ext2fs $TEST
    EXT2FS=$?
    test_passed hostfs $TEST
    HOSTFS=$?
    echo -e "| $TEST | $EXT2FS | $HOSTFS | $RAMFS |"

  done < "$TESTS"

}

function test_passed() {

  fs=$1
  test=$2
  if [[ ! -z $(cat "$fs"_tests_passed.txt | grep $test ) ]]
  then
    return 1
  else
    return 0
  fi

}

TESTS=tests_alltests.txt
FS=ext2fs
run_tests $TESTS

FS=hostfs
run_tests $TESTS

FS=ramfs
run_tests $TESTS

show_stats

# Strip old matrix from readme first
TRIM_LINE=$(grep -n -m 1 "## TEST MATRIX" README.md | cut -d : -f 1)
SEARCH_STRING="$TRIM_LINE,$ d"
sed -i "$SEARCH_STRING"  README.md
generate_matrix >> README.md
