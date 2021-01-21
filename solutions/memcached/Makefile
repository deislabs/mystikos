.PHONY: all app cpio

TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
OPTS = --trace-syscalls
SERVICE_ADD=localhost
SERVICE_PORT=11211

all: myst cpio

run: 
	# Kill the running instance of the server before exit.
	@ echo -e "\n------starting memcached server------\n"
	# Launch the Memcached Server
	$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/memcached -u root start &
	@echo "Run test client outside of the Enclave ..."
	# Launch client test app
	python3 memcached_test.py $(SERVICE_ADD) $(SERVICE_PORT)

run-host: clean all
	docker stop memcached-myst || true
	docker run --name memcached-myst --rm -d -p 11211:11211 memcached:1.6.9-alpine memcached -m 64
	python3 memcached_test.py $(SERVICE_ADD) $(SERVICE_PORT)
	docker stop memcached-myst

gdb: clean all
	@ echo -e "\n------start debugging memcached server------\n"
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/memcached

myst:
	$(MAKE) -C $(TOP)/tools/myst

app: clean
	$(TOP)/scripts/appbuilder Dockerfile

cpio: app
	$(MYST) mkcpio $(APPDIR) rootfs

clean:
	rm -rf rootfs $(APPDIR)
