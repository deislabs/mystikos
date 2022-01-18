FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["hello", "hello/"]
WORKDIR "/src/hello"
RUN dotnet publish -o /app/build --self-contained true -r linux-x64

FROM mcr.microsoft.com/dotnet/runtime:6.0

WORKDIR /app
COPY --from=build /app/build .
