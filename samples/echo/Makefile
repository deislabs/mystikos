TOP=$(abspath ../..)
include $(TOP)/defs.mak

CC = $(MUSL_GCC)

TARGET = $(APPDIR)/bin/echo

APPDIR=$(CURDIR)/appdir

CFLAGS = -fPIC -g -Wall -Werror

LIBS = $(LIBDIR)/liboesdkenclave.a

INCLUDES += -I$(OE_INCDIR)
INCLUDES += -I$(INCDIR)
INCLUDES += -I$(OE_INCDIR)/openenclave/3rdparty
INCLUDES += -I$(SUBOBJDIR)

SOURCES = echo_t.c echo.c

OBJECTS = $(addprefix $(SUBOBJDIR)/, $(SOURCES:.c=.o))

all: $(OBJECTS)
	$(MAKE) -C ../../tools/libos
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(OBJECTS) $(LDFLAGS) $(LIBS)
	$(LIBOS) mkcpio appdir rootfs

ifdef STRACE
OPTS += --strace
endif

run:
	$(LIBOS_EXEC) $(OPTS) rootfs /bin/echo $(OPTS)

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
