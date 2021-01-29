FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
WORKDIR /src
COPY ["HelloWorld", "HelloWorld/"]
WORKDIR "/src/HelloWorld"
RUN dotnet publish "HelloWorld.csproj" -c Release -o /app/build --self-contained true -r alpine-x64 /p:PublishTrimmed=true

FROM alpine:3.10

RUN apk add --no-cache libstdc++ libintl icu-libs

WORKDIR /app
COPY --from=build /app/build .

ENTRYPOINT [ "./HelloWorld" ]
