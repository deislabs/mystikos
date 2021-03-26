FROM mcr.microsoft.com/dotnet/sdk:5.0-alpine AS build
WORKDIR /src
COPY ["hello", "hello/"]
WORKDIR "/src/hello"
RUN dotnet build "hello.csproj" -c Debug -r alpine-x64

