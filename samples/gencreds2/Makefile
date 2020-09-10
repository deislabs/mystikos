TOP=$(abspath ../..)
include $(TOP)/defs.mak

TARGET = $(APPDIR)/bin/gencreds2

APPDIR=$(CURDIR)/appdir
LIBOS = $(BINDIR)/libos
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=/lib -L$(APPDIR)/lib -loesdk -lmbedcrypto -lmbedx509
INCLUDES = -I$(OE_INCDIR) -I$(INCDIR) -I$(OE_INCDIR)/openenclave/3rdparty

export LD_LIBRARY_PATH=$(APPDIR)/lib

all: libos
	mkdir -p $(APPDIR)/bin
	mkdir -p $(APPDIR)/lib
	cp $(LIBDIR)/liboesdk.so $(APPDIR)/lib
	$(MUSL_GCC) $(CFLAGS) $(INCLUDES) -o $(TARGET) gencreds2.c $(LDFLAGS)
	$(LIBOS) mkcpio appdir rootfs

ifdef STRACE
OPTS += --strace
endif

run:
	$(LIBOS) exec $(OPTS) rootfs /bin/gencreds2 $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -f rootfs $(TARGET)
