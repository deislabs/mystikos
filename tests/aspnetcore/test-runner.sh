#!/bin/bash

# tolerance for flaky tests
TOLERATE=1

if [ -f "FAILED" ]; then
  rm FAILED
fi

for F in $(cat unit-tests.passed) ; do
  echo "=========================================="
  echo "Running test= $F"
  timeout -k 60s -s KILL 60 make one TEST="$F" 2>&1
  ret_val=$?
  echo "Return code= $ret_val"
  if [[ $ret_val != 0 ]] ; then
    echo $F >> FAILED
  fi
done

if [[ -f "FAILED" ]] ; then
  NUM_FAIL=$(wc -l < FAILED)
  echo "=========================================="
  echo "$NUM_FAIL Failed tests:"
  cat FAILED
  rm FAILED
  echo "=========================================="

  if [[ $NUM_FAIL -gt $TOLERATE ]] ; then
    exit 1
  fi
fi
