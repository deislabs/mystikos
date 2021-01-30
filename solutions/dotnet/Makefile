TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
APPNAME=HelloWorld

#ifdef STRACE
#OPTS += --strace
#endif

all: appdir private.pem

# This will crash due to insufficient heap memory for dotnet runtime.
# Default is 64mb, and the runtime requires at least 512mb.
# Enable after issue 146 is resolved.
#run-unsigned:
#	$(MYST) mkcpio appdir rootfs
#	$(MYST_EXEC) $(OPTS) rootfs /HelloWorld/build/HelloWorld

run: appdir private.pem
	$(MYST) package appdir private.pem config.json
	myst/bin/$(APPNAME) $(OPTS)
	
gdb: appdir private.pem
	$(MYST_GDB) --args myst/bin/$(APPNAME) $(OPTS)

appdir:
	# ATTN: replace the debugger build of dotnet SDK jxyang100/dotnet:alpine
	# with the release version from ACR

	# Compile the C# app and put all required dotnet libraries under
	# $APPNAME/build
	docker run --rm -v${CURDIR}/HelloWorld:/HelloWorld -w /HelloWorld jxyang100/dotnet:alpine /dotnet/dotnet  publish -o build --self-contained true -r alpine-x64 /p:PublishTrimmed=true
	sudo chown $(USER):$(GROUP) -R HelloWorld

	# Remove the unnecessary folder.
	rm -rf HelloWorld/bin

	# Create appdir out of the docker file and the locally compiled app
	$(APPBUILDER) Dockerfile

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	sudo rm -fr appdir rootfs HelloWorld/build HelloWorld/obj HelloWorld/bin myst private.pem
