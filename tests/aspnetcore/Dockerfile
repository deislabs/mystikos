FROM mcr.microsoft.com/dotnet-buildtools/prereqs:ubuntu-16.04-a50a721-20191120200116 as builder

WORKDIR /app
RUN git clone --branch v6.0.0-preview.2.21154.6 --recursive https://github.com/dotnet/aspnetcore
WORKDIR /app/aspnetcore
RUN ./eng/build.sh -nobl -c Debug \
    --arch x64 --pack --all \
	--no-build-nodejs --no-build-java \
	p:SkipTestBuild=false; \
	exit 0 # ignore build errors

FROM mcr.microsoft.com/dotnet/runtime:6.0

COPY --from=builder /app/aspnetcore /aspnetcore
