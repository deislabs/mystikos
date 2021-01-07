.PHONY: all app cpio

TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
TESTSDIR_HOST=$(CURDIR)/$(APPDIR)/tests
TESTSDIR_MYST=/tests
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: myst cpio

#OPTS = --trace-syscalls

run: 
	@ echo -e "\n------starting msgpack-c cpp unit tests------\n"
	$(foreach test, $(shell ls $(TESTSDIR_HOST)), $(MYST) exec rootfs $(TESTSDIR_MYST)/$(test) $(OPTS) $(NL))

myst:
	$(MAKE) -C $(TOP)/tools/myst

app: clean
	$(TOP)/scripts/appbuilder Dockerfile

cpio: app
	$(MYST) mkcpio $(APPDIR) rootfs

clean:
	rm -rf rootfs $(APPDIR)
