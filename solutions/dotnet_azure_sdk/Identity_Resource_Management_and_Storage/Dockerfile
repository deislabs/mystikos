# stage 1: build
# See https://mcr.microsoft.com/en-us/product/dotnet/sdk/tags for available tags
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /app
COPY src .
RUN dotnet publish -o publish -f net6.0 -r linux-musl-x64 /p:PublishTrimmed=true

# stage 2: run
# See https://mcr.microsoft.com/en-us/product/dotnet/aspnet/tags for available tags
FROM mcr.microsoft.com/dotnet/aspnet:6.0-alpine
WORKDIR /app
RUN apk add --no-cache icu-libs
COPY --from=build /app/publish .
