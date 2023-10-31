FROM mcr.microsoft.com/dotnet-buildtools/prereqs:ubuntu-16.04-20210311173918-cb64fc0 as builder

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
            -priority1 \ 
            -skipstressdependencies \
            -skiptestwrappers \
            /p:LibrariesConfiguration=Debug

FROM mcr.microsoft.com/dotnet/runtime:6.0
RUN apt update && apt install -y libicu-dev
WORKDIR /coreclr-tests-all
COPY --from=builder /build/runtime/artifacts/tests/coreclr/Linux.x64.Debug/ ./
