TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wall -Wl,-rpath=$(MUSL_LIB)
LDFLAGS1 = -Werror -lssl -lcrypto
TEST_ENGINE_PATH = $(CURDIR)/libmyst_sign_test_engine.so
TEST_ENGINE_ID = signing-engine-test
PRIVATE = $(CURDIR)/private.pem

all: myst rootfs $(PRIVATE)

rootfs: signing-engine-test.c hello.c
	$(MAKE) clean
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -shared -o $(TEST_ENGINE_PATH) signing-engine-test.c $(LDFLAGS) $(LDFLAGS1)
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/hello hello.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

$(PRIVATE):
	openssl genrsa -out $(PRIVATE) -3 3072
	openssl genrsa -out wrongprivate.pem  3072

tests: rootfs $(PRIVATE)
	$(RUNTEST) $(MYST) sign rootfs NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key $(PRIVATE)
	$(RUNTEST) ./hello.signed/bin/myst $(EXEC) hello.signed/rootfs /bin/hello
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-engine-valid)\n\n"

	$(MYST) sign rootfs NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path /tmp/no_there --signing-engine-key $(PRIVATE) 2> 1 || sed -i 's/^.*mystikos/mystikos/' 1 || $(RUNTEST) diff 1 expected_invalid_parameter_op1.txt
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-engine-failed-engine-path)\n\n"
	
	$(MYST) sign rootfs NULL config.json --signing-engine-name myst-sign-test-bogus-id --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key $(PRIVATE) 2> 2 || sed -i 's/^.*mystikos/mystikos/' 2 || $(RUNTEST) diff 2 expected_invalid_parameter_op2.txt
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-engine-failed-engine-id)\n\n"
	
	$(MYST) sign rootfs NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key 'boguskey' 2> 3  || sed -i 's/^.*mystikos/mystikos/' 3 || $(RUNTEST) diff 3 expected_invalid_parameter_op1.txt
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-engine-failed-key-id)\n\n"
	
	$(MYST) sign rootfs NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key wrongprivate.pem 2> 4  || sed -i 's/^.*mystikos/mystikos/' 4 || $(RUNTEST) diff 4 expected_invalid_signing_key_op.txt
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-engine-sign-wrong)\n\n"

OPTS =

ifdef STRACE
OPTS += --strace
endif

ifdef PERF
OPTS += --perf
endif

OPTS += --thread-stack-size=1048576

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(PRIVATE) wrongprivate.pem $(APPDIR) rootfs hello.signed 1 2 3 4
