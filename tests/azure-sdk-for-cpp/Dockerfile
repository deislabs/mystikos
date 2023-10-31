FROM alpine:3.13.4

RUN apk update && apk upgrade \
    && apk add --no-cache build-base curl zip unzip tar openssl-dev curl-dev \
    && apk add --no-cache g++ wget libxml2-dev make ninja gcc cmake git

# Previously this Dockerfile checkouts commit 8fcc1df085eb7dad87084813e19fa6c362bb6734
# But git clone doesn't support cloning at a specific commit, so replaced with a tag that include commit 8fcc1df
RUN git clone --depth 1 --single-branch --branch azure-storage-common_12.1.0 https://github.com/Azure/azure-sdk-for-cpp.git

RUN cd azure-sdk-for-cpp \
        && mkdir build && cd build \
		&& cmake .. -DBUILD_TRANSPORT_CURL=ON -DCMAKE_BUILD_TYPE=Debug -DBUILD_STORAGE_SAMPLES=ON -DBUILD_TESTING=ON \
		&& cmake --build .
