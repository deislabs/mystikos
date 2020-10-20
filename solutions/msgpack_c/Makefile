.PHONY: all app cpio

TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
TESTSDIR_HOST=$(CURDIR)/$(APPDIR)/tests
TESTSDIR_LIBOS=/tests
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: libos cpio

#OPTS = --trace-syscalls

run: 
	@ echo -e "\n------starting msgpack-c cpp unit tests------\n"
	$(foreach test, $(shell ls $(TESTSDIR_HOST)), $(LIBOS) exec rootfs $(TESTSDIR_LIBOS)/$(test) $(OPTS) $(NL))

libos:
	$(MAKE) -C $(TOP)/tools/libos

app: clean
	$(TOP)/scripts/appbuilder Dockerfile

cpio: app
	$(LIBOS) mkcpio $(APPDIR) rootfs

clean:
	rm -rf rootfs $(APPDIR)
