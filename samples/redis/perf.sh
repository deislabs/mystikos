#!/bin/bash

function benchmark() {
    # sudo apt-get install -y redis-tools

    NUM_CLIENT=${1:-"1"}
    REQUESTS=${2:-"10000"}

    rm benchmark_data.txt

    make native-server
    echo "NATIVE>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>NATIVE" >> benchmark_data.txt
    redis-benchmark -q $3 -h 127.0.0.1 -p 6379 -c $NUM_CLIENT -n $REQUESTS > temp
    OP=$(cat temp)
    cat temp >> benchmark_data.txt
    NAT=$(echo $OP | grep PING_BULK | grep -oP '.*(?= requests)' | tail -1 | awk 'NF>1{print $NF}')
    ./kill.sh

    make ext2-server
    echo "SGX>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>SGX" >> benchmark_data.txt
    redis-benchmark -q $3 -h 127.0.0.1 -p 6379 -c $NUM_CLIENT -n $REQUESTS > temp
    OP=$(cat temp)
    cat temp >> benchmark_data.txt
    SG=$(echo $OP | grep PING_BULK | grep -oP '.*(?= requests)' | tail -1 | awk 'NF>1{print $NF}')
    ./kill.sh
    
    make ext2-server TARGET=linux
    echo "LINUX>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>LINUX" >> benchmark_data.txt
    set -ex
    redis-benchmark -q $3 -h 127.0.0.1 -p 6379 -c $NUM_CLIENT -n $REQUESTS > temp
    OP=$(cat temp)
    cat temp >> benchmark_data.txt
    set +ex
    LIN=$(echo $OP | grep PING_BULK | grep -oP '.*(?= requests)' | tail -1 | awk 'NF>1{print $NF}')
    ./kill.sh

    if [ ! -z "$3" ]; then
        echo "$NUM_CLIENT $REQUESTS $NAT $SG $LIN" >> perf.txt
    else
        cat benchmark_data.txt 
        VALS="PING_INLINE PING_BULK SET GET INCR LPUSH: RPUSH LPOP RPOP SADD HSET SPOP LPUSH LRANGE_100 LRANGE_300 LRANGE_500 LRANGE_600 MSET"
        echo " "
        for val in $VALS; do
            echo " "
            cat benchmark_data.txt | grep -w $val
        done
    fi
}

function sample() {
    export TIMEFORMAT=%R
    TR=10000
    DEC=2
    for (( c=1; c<=10; c++ ))
    do  
        # Outside of mystikos
        NATIVE=$(make native 2>&1 | tail -2 | head -1)
        TRN=$(python -c "print(round(($TR/$NATIVE),$DEC))")

        # Inside mystikos 
            # SGX
        SGX=$(make ext2 2>&1 | tail -2 | head -1)
        TRS=$(python -c "print(round(($TR/$SGX),$DEC))")

            # Linux
        LINUX=$(make ext2 TARGET=linux 2>&1 | tail -2 | head -1)
        TRL=$(python -c "print(round(($TR/$LINUX),$DEC))")

        echo "$NATIVE $SGX $LINUX $TRN $TRS $TRL"
    done
}

if [ -z $3 ]; then
    benchmark $1 $2
else
    echo "Running permutations"
    CLIENTS="1 5 10 100"
    TRANSACTIONS="10000 25000 50000"
    for client in $CLIENTS; do
        for tran in $TRANSACTIONS; do
            benchmark $client $tran "-t ping"
        done
    done
fi
