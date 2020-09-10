TOP=$(abspath ../..)
include $(TOP)/defs.mak

CC = $(MUSL_GCC)

INCLUDES = -I$(OE_INCDIR) -I$(INCDIR)

TARGET = $(LIBDIR)/liboesdkenclave.a

CFLAGS = -fPIC

all:
	mkdir -p $(LIBDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -shared -o $(TARGET) enclave.c
	@ echo "created $(TARGET)"

tests:

clean:
	rm -f $(TARGET)
