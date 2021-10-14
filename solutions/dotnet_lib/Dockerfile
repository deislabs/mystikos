FROM mcr.microsoft.com/dotnet-buildtools/prereqs:alpine-3.9-WithNode-0fc54a3-20190918214015 as builder
 
WORKDIR /build
RUN git clone --depth 1 --single-branch --branch v5.0.10 https://github.com/dotnet/runtime.git
WORKDIR /build/runtime/
 
# Include keep native symbols commit
RUN git fetch origin main \
    # Checkout tagged runtime branch
    && git checkout v5.0.10 \
    # Include -keepnativesymbols commit
    && git cherry-pick -n 2f1694ea116cc9819644382861690f17f1c8517b
 
# Build clr+libs+clr.tests in debug
RUN ./build.sh -subset clr+libs+libs.tests \
    # dotnet build by default creates stripped binaries
    # with separate files with debug symbols. oe-gdb doesn't
    # support that - https://github.com/openenclave/openenclave/issues/3789
    -keepnativesymbols true \
    /p:RuntimeOS=linux-musl \
    /p:OutputRid=linux-musl-x64

COPY tests.proj ./src/libraries/tests.proj

# Run tests
# RUN ./build.sh -subset libs.tests -test -testnobuild \
#     /p:RuntimeOS=linux-musl \
#     /p:OutputRid=linux-musl-x64
