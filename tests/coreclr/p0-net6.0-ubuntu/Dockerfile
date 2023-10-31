FROM mcr.microsoft.com/dotnet-buildtools/prereqs:ubuntu-16.04-20200508132555-78cbb55 as builder

WORKDIR /build
RUN git clone --depth 1 --single-branch --branch release/6.0 https://github.com/dotnet/runtime.git
WORKDIR /build/runtime/

# Build clr+libs+clr.tests in debug
RUN ./build.sh clr+libs \
            # dotnet build by default creates stripped binaries
            # with separate files with debug symbols. oe-gdb doesn't
            # support that - https://github.com/openenclave/openenclave/issues/3789
            -keepnativesymbols true \
    && ./src/tests/build.sh \
            debug \
            # only build for p0 tests
            # for p1 tests, uncomment next line
            #-priority1 \ 
            -skiptestwrappers \
            /p:LibrariesConfiguration=Debug

FROM mcr.microsoft.com/dotnet/runtime:6.0
WORKDIR /coreclr-tests-all
RUN apt update && apt install -y libicu-dev
COPY --from=builder /build/runtime/artifacts/tests/coreclr/Linux.x64.Debug/ ./