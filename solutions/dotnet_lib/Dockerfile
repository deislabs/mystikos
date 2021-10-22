FROM mcr.microsoft.com/dotnet-buildtools/prereqs:alpine-3.9-WithNode-0fc54a3-20190918214015 as builder

WORKDIR /build
RUN git clone --depth 1 --single-branch --branch v5.0.11 https://github.com/dotnet/runtime.git
WORKDIR /build/runtime/

# Build clr+libs+libs.tests in Release
RUN ./build.sh -subset clr+libs+libs.tests \
    -c Release -rc Release -lc Release \
    /p:RuntimeOS=linux-musl /p:OutputRid=linux-musl-x64

# To run all library tests
# RUN ./build.sh -subset libs.tests -test -testnobuild \
#     -c Release -rc Release -lc Release \
#     /p:RuntimeOS=linux-musl /p:OutputRid=linux-musl-x64

# https://hub.docker.com/_/microsoft-dotnet-runtime/
FROM mcr.microsoft.com/dotnet/runtime:5.0.11-alpine3.13
WORKDIR /dotnet-lib-release
COPY --from=builder /build/runtime/ ./

# Grab the correct .NET runtime so we can run the tests
# More info: we need correct version of SDK + runtime to run a test, 
RUN cp -r ./artifacts/bin/testhost/net5.0-Linux-Release-x64/shared/Microsoft.NETCore.App/5.0.11/ ./.dotnet/shared/Microsoft.NETCore.App/
