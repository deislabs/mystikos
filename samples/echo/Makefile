TOP=$(abspath ../..)
include $(TOP)/defs.mak

CC = $(MUSL_GCC)

TARGET = $(APPDIR)/bin/echo

APPDIR=$(CURDIR)/appdir

LIBOS = $(BINDIR)/libos

CFLAGS = -fPIC -g -Wall -Werror

LDFLAGS = -Wl,-rpath=/lib -L$(APPDIR)/lib -loesdk

INCLUDES += -I$(OE_INCDIR)
INCLUDES += -I$(INCDIR)
INCLUDES += -I$(OE_INCDIR)/openenclave/3rdparty
INCLUDES += -I$(SUBOBJDIR)

SOURCES = echo_t.c echo.c

OBJECTS = $(addprefix $(SUBOBJDIR)/, $(SOURCES:.c=.o))

all: $(OBJECTS)
	$(MAKE) -C ../../tools/libos
	mkdir -p $(APPDIR)/bin
	mkdir -p $(APPDIR)/lib
	cp $(LIBDIR)/liboesdkenclave.a $(APPDIR)/lib
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	$(LIBOS) mkcpio appdir rootfs

ifdef STRACE
OPTS += --strace
endif

run:
	$(LIBOS) exec $(OPTS) rootfs /bin/echo $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

$(SUBOBJDIR)/echo.o : echo.c
	mkdir -p $(SUBOBJDIR)
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

$(SUBOBJDIR)/echo_t.o : $(SUBOBJDIR)/echo_t.c
	mkdir -p $(SUBOBJDIR)
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

$(SUBOBJDIR)/echo_t.c: echo.edl
	$(EDGER8R) $(EDGER8R_TRUSTED_OPTS) echo.edl

CLEAN += $(OBJECTS) $(SUBOBJDIR)/echo_t.c $(APPDIR)

clean:
	rm -rf rootfs $(CLEAN)
