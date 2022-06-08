FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["dotnet_client", "dotnet_client/"]
WORKDIR "/src/dotnet_client"
RUN dotnet publish -o /app/build --self-contained true -r linux-x64

FROM mcr.microsoft.com/dotnet/runtime:6.0

WORKDIR /app
# Create hostfs mount target directory
RUN mkdir -p /mnt/host
COPY --from=build /app/build .
