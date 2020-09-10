TOP=$(abspath ../..)
include $(TOP)/defs.mak

CC = $(MUSL_GCC)

INCLUDES = -I$(OE_INCDIR) -I$(INCDIR)

TARGET = $(LIBDIR)/liboesdk.so

CFLAGS = -fPIC

all:
	mkdir -p $(LIBDIR)
	$(MUSL_GCC) $(CFLAGS) $(INCLUDES) -shared -o $(TARGET)  oesdk.c
	@ echo "created $(TARGET)"

tests:

clean:
	rm -f $(TARGET)
