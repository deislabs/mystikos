# pre-request, python3.6+ and pymemcache package, or run the client directly from container
.PHONY: all

TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER    = $(TOP)/scripts/appbuilder
APPDIR        = appdir
APP_NAME      = memcached
CLIENT_IMAGE  = myst-memcached-client
SERVICE_ADD=localhost
SERVICE_PORT=11211
LAUNCH_WAIT   = 10	# waiting time in seconds for service launch
SHUTDOWN_WAIT = 1  	# waiting time in seconds before service being terminated
# OPTS += --strace

all: myst build-package

_run: run-package

run:
	$(RUNTEST) make -C $(CURDIR) _run

run-package: 
	# Kill the server from a previous run if it wasn't shut down properly.
	test -f $(APP_NAME).pid && kill -9 `cat $(APP_NAME).pid` || true
	# Launch the Memcached Server
	@echo "\n------starting memcached server------\n"
	myst/bin/$(APP_NAME) -u root $(OPTS) & echo $$! > $(APP_NAME).pid
	sleep $(LAUNCH_WAIT)
	# Launch client test app
	@echo "\n------Run test client outside of the Enclave------\n"
	docker run --network host --rm $(CLIENT_IMAGE) $(SERVICE_ADD) $(SERVICE_PORT)
	# Kill the running instance of the server before exit.
	sleep $(SHUTDOWN_WAIT)
	test -f $(APP_NAME).pid && kill -9 `cat $(APP_NAME).pid` && rm $(APP_NAME).pid || true

run-cpio: build-cpio
	# Kill the server from a previous run if it wasn't shut down properly.
	test -f $(APP_NAME).pid && kill -9 `cat $(APP_NAME).pid` || true
	# Launch the Memcached Server
	@echo "\n------starting memcached server------\n"
	$(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/memcached -u root & echo $$! > $(APP_NAME).pid
	sleep $(LAUNCH_WAIT)
	# Launch client test app
	@echo "\n------Run test client outside of the Enclave------\n"
	docker run --network host --rm $(CLIENT_IMAGE) $(SERVICE_ADD) $(SERVICE_PORT)
	# Kill the running instance of the server before exit.
	sleep $(SHUTDOWN_WAIT)
	test -f $(APP_NAME).pid && kill -9 `cat $(APP_NAME).pid` && rm $(APP_NAME).pid || true

run-host: clean
	docker stop memcached-myst || true
	docker run --name memcached-myst --rm -d -p 11211:11211 memcached:1.6.9-alpine memcached -m 64
	sleep $(LAUNCH_WAIT)
	python3 memcached_test.py $(SERVICE_ADD) $(SERVICE_PORT)
	docker stop memcached-myst

gdb: clean build-cpio
	@echo "\n------start debugging memcached server------\n"
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) rootfs /usr/local/bin/memcached -u root

myst:
	$(MAKE) -C $(TOP)/tools/myst

appdir: 
	@echo "\n------Building appdir------\n"
	$(APPBUILDER) -m Dockerfile.server
	@echo "\n------Building client client application container------\n"
	docker build -t $(CLIENT_IMAGE) -f Dockerfile.client .

build-cpio: appdir
	$(MYST) mkcpio $(APPDIR) rootfs

build-package: appdir private.pem
	$(MYST) package-sgx $(APPDIR) private.pem config.json

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	rm -rf rootfs $(APPDIR) myst private.pem 

clean-all: clean
	rm -f $(APP_NAME).pid