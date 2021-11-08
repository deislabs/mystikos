FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
WORKDIR /src
COPY ["TEEAware", "TEEAware/"]
WORKDIR "/src/TEEAware"
RUN dotnet publish "TEEAware.csproj" -c Release -o /app/build --self-contained true -r alpine-x64

FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-alpine

RUN apk add --no-cache icu-libs

WORKDIR /app
COPY --from=build /app/build .

ENTRYPOINT [ "./TEEAware" ]
