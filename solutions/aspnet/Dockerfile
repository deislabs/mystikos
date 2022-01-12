#######################################################################
# To run this container without Mystikos:
#     docker run -p 5050:5050 `docker build -q .`
#######################################################################

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 5050

ENV ASPNETCORE_URLS=http://*:5050

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish "/src/webapp.csproj" -c Release -o /app/build

FROM base AS final
WORKDIR /app
COPY --from=build /app/build .
WORKDIR /
ENTRYPOINT ["/app/webapp"]
