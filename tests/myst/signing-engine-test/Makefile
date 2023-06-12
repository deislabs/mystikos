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
	$(MYST) mkcpio $(APPDIR) cpiorootfs
	$(MYST) mkext2 $(APPDIR) ext2rootfs
	$(MAKE) roothash
	touch rootfs

roothash:
	$(MYST) fssig --roothash ext2rootfs > roothash

$(PRIVATE):
	openssl genrsa -out $(PRIVATE) -3 3072
	openssl genrsa -out wrongprivate.pem  3072

tests: rootfs $(PRIVATE) 
	$(MAKE) test-ext2
	$(MAKE) test-cpio

verify:
	oesign dump --enclave-image=./hello.signed/lib/openenclave/mystenc.so		# Verify without package mode enclave
	myst dump-sgx ./myst/bin/hello												# Verify packaged binary

test-ext2: rootfs roothash
	$(RUNTEST) $(MYST) package-sgx --roothash=roothash NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key $(PRIVATE)
	$(RUNTEST) ./myst/bin/hello --rootfs=ext2rootfs				# METHOD 1
	MYST_ROOTFS_PATH=ext2rootfs $(RUNTEST) ./myst/bin/hello		# METHOD 2
	rm -rf myst
	@ echo "=== passed test (myst-sign-package-ext2-valid-1)\n\n"

	$(RUNTEST) $(MYST) package-sgx --roothash=roothash NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key $(PRIVATE) --outfile "helloworld"
	$(RUNTEST) ./helloworld --rootfs=ext2rootfs				# METHOD 1
	MYST_ROOTFS_PATH=ext2rootfs	$(RUNTEST) ./helloworld 	# METHOD 2
	rm helloworld
	@ echo "=== passed test (myst-sign-package-ext2-valid-2)\n\n"

	$(RUNTEST) $(MYST) sign ext2rootfs NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key $(PRIVATE) --roothash=roothash
	$(RUNTEST) ./hello.signed/bin/myst $(EXEC) hello.signed/rootfs /bin/hello
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-ext2-engine-valid-1)\n\n"

	mkdir Helloworld
	$(RUNTEST) $(MYST) sign ext2rootfs NULL config.json --outdir "Helloworld" --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key $(PRIVATE) --roothash=roothash
	$(RUNTEST) ./Helloworld/bin/myst $(EXEC) Helloworld/rootfs /bin/hello
	rm -rf Helloworld
	@ echo "=== passed test (myst-sign-ext2-engine-valid-2)\n\n"

	$(MYST) sign ext2rootfs NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path /tmp/no_there --signing-engine-key $(PRIVATE) --roothash=roothash 2> 1 || sed -i 's/^.*mystikos/mystikos/' 1 || $(RUNTEST) diff 1 expected_invalid_parameter_op1.txt
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-ext2-engine-failed-engine-path)\n\n"
	
	$(MYST) sign ext2rootfs NULL config.json --signing-engine-name myst-sign-ext2-test-bogus-id --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key $(PRIVATE) --roothash=roothash 2> 2 || sed -i 's/^.*mystikos/mystikos/' 2 || $(RUNTEST) diff 2 expected_invalid_parameter_op2.txt
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-ext2-engine-failed-engine-id)\n\n"
	
	$(MYST) sign ext2rootfs NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key 'boguskey' 2> 3  || sed -i 's/^.*mystikos/mystikos/' 3 || $(RUNTEST) diff 3 expected_invalid_parameter_op1.txt
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-ext2-engine-failed-key-id)\n\n"
	
	$(MYST) sign ext2rootfs NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key wrongprivate.pem 2> 4  || sed -i 's/^.*mystikos/mystikos/' 4 || $(RUNTEST) diff 4 expected_invalid_signing_key_op.txt
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-ext2-engine-sign-wrong)\n\n"

test-cpio: rootfs
	$(RUNTEST) $(MYST) package-sgx appdir $(PRIVATE) config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key $(PRIVATE)
	$(RUNTEST) ./myst/bin/hello
	rm -rf myst
	@ echo "=== passed test (myst-sign-package-cpio-valid-1)\n\n"

	$(RUNTEST) $(MYST) package-sgx appdir $(PRIVATE) config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key $(PRIVATE) --outfile "helloworld"
	$(RUNTEST) ./helloworld
	rm helloworld
	@ echo "=== passed test (myst-sign-package-cpio-valid-2)\n\n"

	$(RUNTEST) $(MYST) sign cpiorootfs NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key $(PRIVATE)
	$(RUNTEST) ./hello.signed/bin/myst $(EXEC) hello.signed/rootfs /bin/hello
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-cpio-engine-valid-1)\n\n"

	mkdir Helloworld
	$(RUNTEST) $(MYST) sign cpiorootfs NULL config.json --outdir "Helloworld" --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key $(PRIVATE)
	$(RUNTEST) ./Helloworld/bin/myst $(EXEC) Helloworld/rootfs /bin/hello
	rm -rf Helloworld
	@ echo "=== passed test (myst-sign-cpio-engine-valid-2)\n\n"

	$(MYST) sign cpiorootfs NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path /tmp/no_there --signing-engine-key $(PRIVATE) 2> 1 || sed -i 's/^.*mystikos/mystikos/' 1 || $(RUNTEST) diff 1 expected_invalid_parameter_op1.txt
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-cpio-engine-failed-engine-path)\n\n"
	
	$(MYST) sign cpiorootfs NULL config.json --signing-engine-name myst-sign-cpio-test-bogus-id --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key $(PRIVATE) 2> 2 || sed -i 's/^.*mystikos/mystikos/' 2 || $(RUNTEST) diff 2 expected_invalid_parameter_op2.txt
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-cpio-engine-failed-engine-id)\n\n"
	
	$(MYST) sign cpiorootfs NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key 'boguskey' 2> 3  || sed -i 's/^.*mystikos/mystikos/' 3 || $(RUNTEST) diff 3 expected_invalid_parameter_op1.txt
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-cpio-engine-failed-key-id)\n\n"
	
	$(MYST) sign cpiorootfs NULL config.json --signing-engine-name $(TEST_ENGINE_ID) --signing-engine-path $(TEST_ENGINE_PATH) --signing-engine-key wrongprivate.pem 2> 4  || sed -i 's/^.*mystikos/mystikos/' 4 || $(RUNTEST) diff 4 expected_invalid_signing_key_op.txt
	rm -rf hello.signed
	@ echo "=== passed test (myst-sign-cpio-engine-sign-cpio-wrong)\n\n"

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
	rm -rf $(PRIVATE) wrongprivate.pem $(APPDIR) Helloworld ext2rootfs cpiorootfs hello.signed 1 2 3 4 roothash rootfs libmyst* myst*
