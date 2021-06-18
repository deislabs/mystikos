FROM alpine:3.13.4

RUN apk update && apk upgrade \
    && apk add --no-cache build-base curl zip unzip tar openssl-dev curl-dev \
    && apk add --no-cache g++ wget libxml2-dev make ninja gcc cmake git

RUN git clone https://github.com/Azure/azure-sdk-for-cpp.git

RUN cd azure-sdk-for-cpp && git checkout 9fd5806c14c222ad17e9f178ccec6eb96dc94f40 \
        && mkdir build && cd build \
		&& cmake .. -DBUILD_TRANSPORT_CURL=ON -DCMAKE_BUILD_TYPE=Debug -DBUILD_STORAGE_SAMPLES=ON -DBUILD_TESTING=ON \
		&& cmake --build .
