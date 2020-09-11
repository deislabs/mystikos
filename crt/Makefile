TOP=$(abspath ..)
include $(TOP)/defs.mak

TARGET = $(LIBDIR)/liboscrt.so

CFLAGS = -m64 -g -fPIC -Werror

INCLUDES = -I$(INCDIR)

SOURCES = $(wildcard *.c)

LDFLAGS1 = -Wl,--sort-section,alignment -Wl,--sort-common -Wl,--gc-sections -Wl,--hash-style=both -Wl,--no-undefined -Wl,--exclude-libs=ALL -nostdlib -nodefaultlibs -nostartfiles

LDFLAGS1 += -Wl,-elibos_crt_enter

LDFLAGS2 = -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--export-dynamic -Wl,-pie -Wl,--build-id -Wl,-z,noexecstack -Wl,-z,now

LIBCC = -lgcc

-include $(TOP)/third_party/enclave-musl/musl/objects.mak

OBJECTS = $(addprefix $(SUBOBJDIR)/,$(SOURCES:.c=.o))

$(TARGET): $(MUSL_OBJECTS) $(OBJECTS)
	mkdir -p $(LIBDIR)
	$(CC) -o $@ $(LDFLAGS1) $(OBJECTS) $(MUSL_OBJECTS) $(LIBCC) $(LDFLAGS2)

$(SUBOBJDIR)/%.o: %.c
	mkdir -p $(SUBOBJDIR)
	$(shell mkdir -p $(shell dirname $@))
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -f $(OBJECTS) $(TARGET)

tests:
