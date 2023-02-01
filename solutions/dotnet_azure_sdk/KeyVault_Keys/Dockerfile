# stage 1: build
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /app
COPY src .
RUN dotnet publish -o publish -r linux-x64 /p:PublishTrimmed=true

# stage 2: run
FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-alpine
FROM mcr.microsoft.com/dotnet/aspnet:6.0-bullseye-slim AS base

WORKDIR /app
COPY --from=build /app/publish .
