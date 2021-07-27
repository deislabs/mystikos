

function benchmark() {
    # sudo apt-get install -y redis-tools

    rm benchmark_data.txt

    make native-server
    echo "NATIVE>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>NATIVE" >> benchmark_data.txt
    redis-benchmark -q -h 127.0.0.1 -p 6379 -c 5 -n 10000 >> benchmark_data.txt
    ./kill.sh

    make ext2-server
    echo "SGX>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>SGX" >> benchmark_data.txt
    redis-benchmark -q -h 127.0.0.1 -p 6379 -c 5 -n 10000 >> benchmark_data.txt
    ./kill.sh
    
    make ext2-server TARGET=linux
    echo "LINUX>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>LINUX" >> benchmark_data.txt
    redis-benchmark -q -h 127.0.0.1 -p 6379 -c 5 -n 10000 >> benchmark_data.txt
    ./kill.sh

    cat benchmark_data.txt 

    VALS="PING_INLINE PING_BULK SET GET INCR LPUSH: RPUSH LPOP RPOP SADD HSET SPOP LPUSH LRANGE_100 LRANGE_300 LRANGE_500 LRANGE_600 MSET"

    echo " "
    for val in $VALS; do
        echo " "
        cat benchmark_data.txt | grep -w $val
    done
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

benchmark
