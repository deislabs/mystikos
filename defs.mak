LIBDIR=$(TOP)/build/lib

BINDIR=$(TOP)/build/bin

INCDIR=$(TOP)/build/include

EDGER8R=$(BINDIR)/oeedger8r

OEENCLAVE_LDFLAGS = -nostdlib -nodefaultlibs -nostartfiles -Wl,--no-undefined -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--export-dynamic -Wl,-pie -Wl,--build-id -Wl,-z,noexecstack -Wl,-z,now -Wl,-gc-sections $(LIBDIR)/oeenclave.o

OEENCLAVE_CFLAGS = -nostdinc -m64 -fPIE -ftls-model=local-exec -fvisibility=hidden -fstack-protector-strong -fno-omit-frame-pointer -ffunction-sections -fdata-sections

OEHOST_LDFLAGS = -L$(LIBDIR)/openenclave/host -Wl,-z,noexecstack -loehost -ldl -lpthread -lsgx_enclave_common -lsgx_dcap_ql -lssl -lcrypto

define NL

endef
