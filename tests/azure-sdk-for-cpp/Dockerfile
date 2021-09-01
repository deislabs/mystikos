FROM alpine:3.13.4

RUN apk update && apk upgrade \
    && apk add --no-cache build-base curl zip unzip tar openssl-dev curl-dev \
    && apk add --no-cache g++ wget libxml2-dev make ninja gcc cmake git

RUN git clone https://github.com/Azure/azure-sdk-for-cpp.git

RUN cd azure-sdk-for-cpp && git checkout 8fcc1df085eb7dad87084813e19fa6c362bb6734 \
        && mkdir build && cd build \
		&& cmake .. -DBUILD_TRANSPORT_CURL=ON -DCMAKE_BUILD_TYPE=Debug -DBUILD_STORAGE_SAMPLES=ON -DBUILD_TESTING=ON \
		&& cmake --build .
