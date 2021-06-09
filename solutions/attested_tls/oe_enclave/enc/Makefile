CFLAGS=$(shell pkg-config oeenclave-gcc --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-g++ --cflags)
LDFLAGS=$(shell pkg-config oeenclave-g++ --libs)
LDFLAGS+=$(shell pkg-config oeenclave-g++ --variable=mbedtlslibs)
INCDIR=$(shell pkg-config oeenclave-gcc --variable=includedir)

.PHONY: all build clean run

all:
	$(MAKE) build
	$(MAKE) sign

build:
	oeedger8r ../tlssrv.edl --trusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) -std=c++11 tlssrv.cpp
	$(CXX) -c $(CFLAGS) $(CINCLUDES) gencreds.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) tlssrv_t.c
	$(CXX) -o tlssrv_enc tlssrv.o gencreds.o tlssrv_t.o $(LDFLAGS) -loehostsock -loehostresolver -loecore -loelibc -loesyscall

private.pem:
	openssl genrsa -out private.pem -3 3072

sign: private.pem
	oesign sign -e tlssrv_enc -c enc.conf -k private.pem

clean:
	rm -f *.o tlssrv_enc tlssrv_enc.signed tlssrv_t.* tlssrv_args.h private.pem
