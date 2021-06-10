SOURCES=$(shell find libgomp.c -type f -name '*.c')

CFLAGS = -I..

define NL


endef

all:
	$(foreach i, $(SOURCES), \
            ( gcc $(CFLAGS) -o $(i).exe $(i) -lgomp || true) \
            $(NL) )
