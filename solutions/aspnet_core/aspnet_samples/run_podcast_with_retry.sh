# wait time between retries
interval=10
# number of retries
retry_count=2

n=1
until [ "$n" -gt $retry_count ]
do
    make run-podcast && exit 0
    echo "run_podcast_with_retry.sh: make run-podcast failed at attempt $n, retrying in $interval seconds"
    sleep $interval

    n=$((n+1))
done

echo "run_podcast_with_retry.sh: failed $n out of $retry_count retry"
exit 1
