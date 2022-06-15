TOP=$(abspath ../../..)
include $(TOP)/defs.mak

all: .built

.built:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
	openssl genrsa -out bad_private.pem -3 3072
	openssl rsa -in bad_private.pem -pubout -out bad_public.pem
	rm -rf appdir
	mkdir -p appdir/bin
	gcc -o appdir/bin/hello hello.c
	$(MYST) mkext2 --force --sign=public.pem:private.pem appdir rootfs.ext2
	$(MYST) fssig --roothash rootfs.ext2 > roothash
	xxd -c 256 -l32 -ps /dev/urandom > bad_roothash
	touch .built

tests: .built
	$(RUNTEST) $(MAKE) __tests

__tests:
	$(MAKE) test1
	$(MAKE) test2
	$(MAKE) test3
	$(MAKE) test4
	$(MAKE) test5
	$(MAKE) test6
	$(MAKE) test7
	$(MAKE) test8
	$(MAKE) test9

# test package with <app_path> == app directory
test1:
	@ echo "=== TEST1"
	$(MYST) package appdir private.pem config.json
	./myst/bin/hello

# test package with --roothash=<filename>
test2:
	@ echo "=== TEST2"
	$(MYST) package --roothash=roothash private.pem config.json
	MYST_ROOTFS_PATH=rootfs.ext2 ./myst/bin/hello

# test package with debug
test3:
	@ echo "=== TEST3"
	$(MYST) package private.pem config_debug.json
	MYST_ROOTFS_PATH=rootfs.ext2 ./myst/bin/hello

# test package with no roothash option, expecting failure
test4:
	@ echo "=== TEST4"
	( $(MYST) package private.pem config.json 2> /dev/null;  test "$$?" -eq "1" )

# test package with an invalid roothash, expecting failure
test5:
	@ echo "=== TEST5"
	$(MYST) package --roothash=bad_roothash private.pem config.json
	( MYST_ROOTFS_PATH=rootfs.ext2 ./myst/bin/hello; test "$$?" -eq "234" )

# test package with --pubkey=<pemfile> (with right public key)
test6:

	@ echo "=== TEST6"
	$(MYST) package --pubkey=public.pem private.pem config.json
	MYST_ROOTFS_PATH=rootfs.ext2 ./myst/bin/hello

# test package with --pubkey=<pemfile> (with wrong public key)
test7:
	@ echo "=== TEST7"
	$(MYST) package --pubkey=bad_public.pem bad_private.pem config.json
	( MYST_ROOTFS_PATH=rootfs.ext2 ./myst/bin/hello 2> /dev/null; test "$$?" -eq "234" )

# test package with nobrk enabled in config
test8:
	@ echo "=== TEST8"
	$(MYST) package appdir private.pem config_enable_nobrk.json
	./myst/bin/hello

# test package with CLI argument --nobrk, expecting failure
test9:
	@ echo "=== TEST9"
	$(MYST) package appdir private.pem config.json
	( ./myst/bin/hello --nobrk 2> result; test "$$?" -eq "255" )

clean:
	rm -rf appdir rootfs.ext2 myst private.pem public.pem bad_roothash roothash bad_public.pem bad_private.pem .built result
