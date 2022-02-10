#!/bin/bash
CURL="curl --location --insecure"

expect() {
    if [[ $1 != $2 ]]; then
        echo "Should be $2, got $1"
        exit 1
    fi
}

client_FlightFinder() {
    echo "Running client for FlightFinder"
    rm -f client.output

    curl -L --insecure 127.0.0.1:5000 || exit 1
    sleep 1
    curl -L --insecure 127.0.0.1:5000 || exit 1
    sleep 1
    curl -L --insecure 127.0.0.1:5000 || exit 1
    sleep 1
    curl -L --insecure 127.0.0.1:5000 || exit 1
    sleep 1
    curl -L --insecure 127.0.0.1:5000 || exit 1
    sleep 1

    touch client.output
    exit 0
}

client_Todo() {
    echo "Running client for TodoApi"

    # Test get /
    ACTUAL=$($CURL http://localhost:5000)
    expect "$ACTUAL" "Hello World!"

    # Test get /todoitems
    ACTUAL=$($CURL http://localhost:5000/todoitems)
    expect "$ACTUAL" "[]"

    # Test post /todoitems
    ACTUAL=$($CURL --request POST 'http://localhost:5000/todoitems' \
            --header 'Content-Type: application/json' \
            --data-raw '{
                "Id": 1,
                "Name": "Some Todo",
                "IsComplete": false
            }')

    # Test get /todoitems/1
    ACTUAL=$($CURL 'http://localhost:5000/todoitems/1')
    expect "$ACTUAL" '{"id":1,"name":"Some Todo","isComplete":false}'

    # Test delete /todoitmes/1
    ACTUAL=$($CURL --request DELETE 'http://localhost:5000/todoitems/1')

    # Test get /todoitems
    ACTUAL=$($CURL http://localhost:5000/todoitems)
    expect "$ACTUAL" "[]"
    exit 0
}

client_Podcast() {
    echo "Running client for dotnet-podcast"

    $CURL 'http://localhost:5000/v1/categories' || exit 1
    sleep 1
    $CURL 'http://localhost:5000/v1/categories' || exit 1
    sleep 1
    $CURL 'http://localhost:5000/v1/categories' || exit 1
    sleep 1
    $CURL 'http://localhost:5000/v1/categories' || exit 1
    sleep 1

    $CURL 'http://localhost:5000/v1/Shows' || exit 1
    sleep 1
    $CURL 'http://localhost:5000/v1/Shows' || exit 1
    sleep 1
    $CURL 'http://localhost:5000/v1/Shows' || exit 1
    sleep 1
    $CURL 'http://localhost:5000/v1/Shows' || exit 1

    exit 0
}

if [[ $1 == "FlightFinder" ]]; then
    client_FlightFinder
elif [[ $1 == "Todo" ]]; then
    client_Todo
elif [[ $1 == "Podcast" ]]; then
    client_Podcast
else
    echo "Invalid argument $1"
fi
