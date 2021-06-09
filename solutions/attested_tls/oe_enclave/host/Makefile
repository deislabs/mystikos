# Detect C and C++ compiler options
# if not gcc and g++, default to clang-7
CC = gcc
CXX = g++
C_COMPILER=$(CC)
CXX_COMPILER=$(CXX)

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tlssrv.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -c $(CFLAGS) $(INCLUDES) tlssrv_u.c
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) host.cpp
	$(CXX) -o tlssrv_host host.o tlssrv_u.o $(LDFLAGS) -L/opt/openenclave/lib/openenclave/enclave -lpthread -lcurl -lmbedtls -lmbedcrypto

clean:
	rm -f tlssrv_host* *.o tlssrv_u.* tlssrv_args.h
