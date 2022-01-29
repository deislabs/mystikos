FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["HelloWorld", "HelloWorld/"]
WORKDIR "/src/HelloWorld"
RUN dotnet publish "HelloWorld.csproj" -c Release -o /app/build --self-contained true -r linux-x64

FROM mcr.microsoft.com/dotnet/runtime:6.0

RUN apt update && apt install -y libicu-dev

WORKDIR /app
COPY --from=build /app/build .

ENTRYPOINT [ "./HelloWorld" ]
