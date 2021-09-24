#!/bin/bash

NUM_FAIL=0
NUM_PASS=0
rm FAILED

for F in $(cat unit-tests.passed) ; do
  echo "=========================================="
  echo "Running test= $F"
  timeout -k 60s -s KILL 60 make one TEST="$F" 2>&1
  ret_val=$?
  echo "Return code= $ret_val"
  if [[ $ret_val != 0 ]] ; then
    echo $F >> FAILED
    NUM_FAIL+=1
  else
    NUM_PASS+=1
  fi
done

if [[ NUM_FAIL != 0 ]] ; then
  echo "=========================================="
  echo "$NUM_FAIL Failed tests:"
  cat FAILED
  rm FAILED
  echo "=========================================="
fi


if [[ NUM_FAIL != 0 ]] ; then
  exit 1
fi