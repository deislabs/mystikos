TOP=$(abspath ../..)
include $(TOP)/defs.mak

all: echo_t.c echo_u.c echo_enc echo_host

INCLUDES = -I$(INCDIR)

echo_t.c:
	$(EDGER8R) --trusted --search-path $(INCDIR) echo.edl

echo_u.c:
	$(EDGER8R) --untrusted --search-path $(INCDIR) echo.edl

echo_enc:
	gcc $(INCLUDES) $(OEENCLAVE_CFLAGS) -c crt.c
	gcc $(INCLUDES) $(OEENCLAVE_CFLAGS) -c enc.c
	gcc $(INCLUDES) $(OEENCLAVE_CFLAGS) -c echo_t.c
	gcc -o enc enc.o echo_t.o crt.o $(OEENCLAVE_LDFLAGS)

echo_host:
	gcc $(INCLUDES) $(OEHOST_CFLAGS) -c host.c
	gcc $(INCLUDES) $(OEHOST_CFLAGS) -c echo_u.c
	gcc -o host host.o echo_u.o $(OEHOST_LDFLAGS)

CLEAN += echo_t.c echo_u.c echo_u.h echo_t.h echo_args.h enc host *.o

clean:
	rm -f $(CLEAN)

tests:
	./host ./enc
