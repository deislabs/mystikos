# stage 1: build
FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
WORKDIR /app
COPY src .
RUN dotnet publish -o publish -f netcoreapp3.1 -r linux-musl-x64 /p:PublishTrimmed=true

# stage 2: run
FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-alpine
WORKDIR /app
RUN apk add --no-cache icu-libs
COPY --from=build /app/publish .
