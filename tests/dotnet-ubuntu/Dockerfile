FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src
COPY ["hello", "hello/"]
WORKDIR "/src/hello"
RUN dotnet publish -o /app/build --self-contained true -r linux-x64

FROM mcr.microsoft.com/dotnet/runtime:5.0

WORKDIR /app
COPY --from=build /app/build .
