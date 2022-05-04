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

run:
	$(MAKE) run-release

run-release: ext2rootfs
	$(RUNTEST) $(MYST_EXEC) --app-config-path config.json $(OPTS) ext2rootfs /app/casablanca/build.release/Release/Binaries/test_runner 

run-debug: ext2rootfs
	$(RUNTEST) $(MYST_EXEC) --app-config-path debug-config.json $(OPTS) ext2rootfs /app/casablanca/build.debug/Release/Binaries/test_runner *_test.so

$(APPDIR):
	$(APPBUILDER) -m -v -d Dockerfile

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
# 
# Set $(TESTCASE) to what you want. It can be all of them:
#TESTCASE=*_test.so
# All tests in a suite:
# TESTCASE=libhttpclient_test.so
# Or it can be a specific test:
TESTCASE=libhttpclient_test.so /name:progress_handler_tests:data_upload_exception
#
# Main PR runs will run against the release build. For these rules you can have control.
# To run with debug:
TESTMODE=debug
# To run in the regular release mode:
#TESTMODE=release

run-cpio: cpio
	$(MYST_EXEC) rootfs --app-config-path debug-config.json $(OPTS) /app/casablanca/build.$(TESTMODE)/Release/Binaries/test_runner $(TESTCASE)

run-ext2: ext2rootfs
	$(MYST_EXEC) ext2rootfs --app-config-path debug-config.json $(OPTS) /app/casablanca/build.$(TESTMODE)/Release/Binaries/test_runner $(TESTCASE)

gdb: ext2rootfs
	$(MYST_GDB) --args $(MYST_EXEC)  --app-config-path debug-config.json $(OPTS) ext2rootfs  /app/casablanca/build.$(TESTMODE)/Release/Binaries/test_runner $(TESTCASE)

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	rm -rf rootfs ext2rootfs $(APPDIR) myst private.pem 
