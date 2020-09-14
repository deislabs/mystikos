TOP=$(abspath ../..)
include $(TOP)/defs.mak

TARGET = $(APPDIR)/bin/gencreds2
CC = $(MUSL_GCC)
APPDIR=$(CURDIR)/appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=/lib -L$(APPDIR)/lib -lmbedcrypto -lmbedx509
INCLUDES = -I$(OE_INCDIR) -I$(INCDIR) -I$(OE_INCDIR)/openenclave/3rdparty
LIBS = $(LIBDIR)/liboesdkenclave.a

export LD_LIBRARY_PATH=$(APPDIR)/lib

all: libos
	mkdir -p $(APPDIR)/bin
	mkdir -p $(APPDIR)/lib
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) gencreds2.c $(LDFLAGS) $(LIBS)
	$(LIBOS) mkcpio appdir rootfs

ifdef STRACE
OPTS += --strace
endif

run:
	$(LIBOS_EXEC) $(OPTS) rootfs /bin/gencreds2 $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -f rootfs $(TARGET)
