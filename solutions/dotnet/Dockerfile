FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["HelloWorld", "HelloWorld/"]
WORKDIR "/src/HelloWorld"
RUN dotnet publish "HelloWorld.csproj" -c Release -o /app/build

FROM mcr.microsoft.com/dotnet/aspnet:6.0

WORKDIR /app
COPY --from=build /app/build .

ENTRYPOINT [ "./HelloWorld" ]
