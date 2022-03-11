.PHONY: all package cpio gdb

TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER    = $(TOP)/scripts/appbuilder
APPDIR        = appdir
APP_NAME      = test_runner

ifdef STRACE
OPTS += --strace
endif

all: package

package: $(APPDIR) private.pem
	$(MYST) package-sgx $(APPDIR) private.pem config.json

run: ext2rootfs
#	myst/bin/$(APP_NAME) $(OPTS)
	$(RUNTEST) $(MYST_EXEC) --app-config-path config.json $(OPTS) ext2rootfs /app/casablanca/build.release/Release/Binaries/test_runner 

$(APPDIR):
	$(APPBUILDER) -v -d Dockerfile

cpio: $(APPDIR)
	$(MYST) mkcpio $(APPDIR) rootfs

ext2rootfs: $(APPDIR)
	$(MYST) mkext2 $(APPDIR) ext2rootfs

# There are 6 test suite come with the CPPRESTSDK, replace the <suite>.so filename to related test suite
# libhttpclient_test.so
# libhttplistener_test.so
# libjson_test.so
# libpplx_test.so
# libstreams_test.so
# liburi_test.so
run-cpio: cpio
	$(MYST_EXEC) rootfs /app/casablanca/build.release/Release/Binaries/test_runner libhttpclient_test.so --app-config-path debug-config.json $(OPTS)

run-ext2: ext2rootfs
	$(MYST_EXEC) ext2rootfs /app/casablanca/build.release/Release/Binaries/test_runner libhttpclient_test.so /name:progress_handler_tests:data_upload_exception --app-config-path debug-config.json $(OPTS)

gdb: ext2rootfs
	$(MYST_GDB) --args $(MYST_EXEC) ext2rootfs /app/casablanca/build.release/Release/Binaries/test_runner libhttplistener_test.so /name:progress_handler_tests:data_upload_exception --app-config-path debug-config.json $(OPTS)

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	rm -rf rootfs ext2rootfs $(APPDIR) myst private.pem 
