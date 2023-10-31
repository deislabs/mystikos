# stage 1 build
FROM alpine:3.12.3 AS cpprest-base-image

RUN apk add --no-cache curl build-base bash git boost-dev cmake zlib-dev openssl-dev ninja

RUN rm -rf /app;mkdir -p /app
	
WORKDIR /app

ADD skip-tests.patch .
RUN git clone --depth 1 --single-branch https://github.com/Microsoft/cpprestsdk.git casablanca
        # apply patch to skip un-wanted tests and compile
RUN cd casablanca;\
        git apply ../skip-tests.patch;\
        mkdir -p build.debug; cd build.debug;\
        cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCPPREST_EXCLUDE_WEBSOCKETS=ON  ..;\
        cd ..;\
        mkdir -p build.release; cd build.release;\
        cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCPPREST_EXCLUDE_WEBSOCKETS=ON  ..;\
        cd ..;\
        ninja -C build.debug;\
        ninja -C build.release;
