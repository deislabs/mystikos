# Base image recommendation from dotnet git repo - https://github.com/dotnet/runtime/blob/main/docs/workflow/building/coreclr/linux-instructions.md#docker-images
FROM mcr.microsoft.com/dotnet-buildtools/prereqs:ubuntu-16.04-a50a721-20191120200116 as builder
ARG TAG=v6.0.0-preview.2.21154.6

WORKDIR /app
RUN git clone --branch ${TAG} --recursive https://github.com/dotnet/aspnetcore
WORKDIR /app/aspnetcore
RUN ./eng/build.sh -nobl -c Debug \
    --arch x64 --all \
	--no-build-nodejs --no-build-java; \
	exit 0 # ignore build errors

FROM mcr.microsoft.com/dotnet/runtime:6.0

WORKDIR /aspnetcore
COPY --from=builder /app/aspnetcore/.dotnet .dotnet
COPY --from=builder /app/aspnetcore/artifacts/bin artifacts/bin/
