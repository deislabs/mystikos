FROM mcr.microsoft.com/dotnet-buildtools/prereqs:ubuntu-16.04-20210311173918-cb64fc0 as builder

WORKDIR /build
RUN git clone --single-branch --branch v5.0.0-rtm.20519.4 https://github.com/dotnet/runtime.git
WORKDIR /build/runtime/

RUN git fetch origin main \
    # Checkout tagged runtime branch
    && git checkout v5.0.0-rtm.20519.4 \
    # Include -keepnativesymbols commit
    && git cherry-pick -n 2f1694ea116cc9819644382861690f17f1c8517b

# Build clr+libs+clr.tests in debug
RUN ./build.sh clr+libs \
            # dotnet build by default creates stripped binaries
            # with separate files with debug symbols. oe-gdb doesn't
            # support that - https://github.com/openenclave/openenclave/issues/3789
            -keepnativesymbols true \
    && ./src/coreclr/build-test.sh \
            debug \
            # only build for p0 tests
            # for p1 tests, uncomment next line
            #-priority1 \ 
            -skipstressdependencies \
            -skiptestwrappers \
            /p:LibrariesConfiguration=Debug

FROM mcr.microsoft.com/dotnet/runtime:5.0
RUN apt install libicuuc-dev
WORKDIR /coreclr-tests-all
COPY --from=builder /build/runtime/artifacts/tests/coreclr/Linux.x64.Debug/ ./