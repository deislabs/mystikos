TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all: libos
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/pthread pthread.c $(LDFLAGS)
	$(LIBOS) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS += --strace
endif

TARGET = sgx
EXEC = exec-$(TARGET)

run: all
	$(LIBOS) $(EXEC) $(OPTS) rootfs /bin/pthread

gdb: all
	$(LIBOS_GDB) --args $(LIBOS) $(EXEC) rootfs /bin/pthread $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs export
