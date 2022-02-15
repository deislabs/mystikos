FROM mcr.microsoft.com/dotnet/sdk:6.0 as BUILDER

# RUN apt update && apt install -y git vim

# All project should use port 5000 for HTTP and 5001 for HTTPS (if exists)
EXPOSE 5000 5001

WORKDIR /aspnet
COPY ./src/samples /aspnet/samples

# Build & Publish all project
ARG DIR_OUTPUT=/built
ARG DOTNET_PUBLISH="dotnet publish -c Release -o ${DIR_OUTPUT}"

# Sample #1 FlightFinder
ARG PROJ_FLIGHT=FlightFinder
WORKDIR /aspnet/samples/${PROJ_FLIGHT}
RUN ${DOTNET_PUBLISH}/${PROJ_FLIGHT}

# Sample #2 TodoApi
ARG PROJ_TODO=TodoApi
WORKDIR /aspnet/samples/${PROJ_TODO}
RUN ${DOTNET_PUBLISH}/${PROJ_TODO}

# Sample #3 Podcast
WORKDIR /aspnet
COPY ./src/dotnet-podcasts /aspnet/dotnet-podcasts

WORKDIR /aspnet/dotnet-podcasts/src/Services/Podcasts/Podcast.API
RUN ${DOTNET_PUBLISH}/dotnet-podcasts

COPY ./appsettings.json /built/dotnet-podcasts

# Extract built apps
FROM mcr.microsoft.com/dotnet/aspnet:6.0

# See https://github.com/dotnet/SqlClient/issues/633#issuecomment-654448189
RUN sed -i 's/CipherString = DEFAULT@SECLEVEL=2/CipherString = DEFAULT@SECLEVEL=1/' /etc/ssl/openssl.cnf

COPY --from=BUILDER /built /built

# ENTRYPOINT [ "dotnet", "/built/FlightFinder/FlightFinder.Server.dll" ]
# ENTRYPOINT [ "/built/TodoApi/TodoApi" ]
# ENTRYPOINT [ "/built/dotnet-podcasts/Podcast.API" ]
