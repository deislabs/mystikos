FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
WORKDIR /src
COPY ["HelloWorld", "HelloWorld/"]
WORKDIR "/src/HelloWorld"
RUN dotnet publish "HelloWorld.csproj" -c Release -o /app/build --self-contained true -r alpine-x64

FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-alpine

RUN apk add --no-cache icu-libs

WORKDIR /app
COPY --from=build /app/build .

ENTRYPOINT [ "./HelloWorld" ]
