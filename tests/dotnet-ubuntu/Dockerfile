FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src
COPY ["hello", "hello/"]
WORKDIR "/src/hello"
ENV PATH="/lib/x86_64-linux-gnu/:/usr/lib/x86_64-linux-gnu/:${PATH}"
RUN dotnet publish -o /app/build --self-contained true -r linux-x64

FROM mcr.microsoft.com/dotnet/runtime:5.0

WORKDIR /app
COPY --from=build /app/build .
# Hack: Copy over libraries to where musl can find them.
RUN rmdir /usr/local/lib && ln -s /lib/x86_64-linux-gnu/ /usr/local/lib && \
	cp /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /lib/x86_64-linux-gnu/ && \
	cp /usr/lib/x86_64-linux-gnu/libicu* /lib/x86_64-linux-gnu/ 
