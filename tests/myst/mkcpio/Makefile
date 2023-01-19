TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
APPNAME = hello
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
LDFLAGS += -L$(LIBDIR) -lopenenclave

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

REDEFINE_TESTS=1

include $(TOP)/rules.mak

tests:
	$(MAKE) test-mkcpio

test-mkcpio:
	rm -rf $(APPDIR) $(APPDIR)2 dir1 dir2 dir1.txt dir2.txt difference1.txt rootfs private.pem public.pem $(APPNAME).signed
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/$(APPNAME) ../hello.c $(LDFLAGS)
	$(PREFIX) $(MYST) mkcpio $(APPDIR) rootfs
	$(PREFIX) $(MYST) excpio rootfs $(APPDIR)2
	sudo chown -R $(USER).$(USER) $(APPDIR) rootfs $(APPDIR)2
	mkdir -p dir1
	mkdir -p dir2
	mv  $(APPDIR) dir1/
	mv  $(APPDIR)2 dir2/$(APPDIR)
	cd dir1 && find . -type f -exec md5sum {} + | sort -k 2 > ../dir1.txt
	cd dir2 && find . -type f -exec md5sum {} + | sort -k 2 > ../dir2.txt
	diff -u dir1.txt dir2.txt
	rm -rf $(APPDIR) $(APPDIR)2 dir1 dir2 dir1.txt dir2.txt difference1.txt rootfs private.pem public.pem $(APPNAME).signed
	@ echo "=== passed test ($(__PROGRAM): test-a)"

