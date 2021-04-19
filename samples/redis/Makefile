.PHONY: all package $(APPDIR) private.pem

TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER    = $(TOP)/scripts/appbuilder
APPDIR        = appdir
APP_NAME      = redis-server
SERVICE_ADDR  = localhost
SERVICE_PORT  = 6379
LAUNCH_WAIT   = 10	# waiting time in seconds for service launch
SHUTDOWN_WAIT = 0  	# waiting time in seconds before service being terminated
# OPTS += --strace

all: package

package: $(APPDIR) private.pem
	cp redis.conf $(APPDIR)/etc/redis.conf
	echo "\n\nport $(SERVICE_PORT)" >> $(APPDIR)/etc/redis.conf
	$(MYST) package-sgx $(APPDIR) private.pem config.json

run: package
	# Kill the server from a previous run if it wasn't shut down properly.
	test -f $(APP_NAME).pid && kill -9 `cat $(APP_NAME).pid` || true
	# Launch the Redis Server
	@ echo -e "\n------starting Redis server------\n"
	myst/bin/$(APP_NAME) $(OPTS) & echo $$! > $(APP_NAME).pid
	sleep $(LAUNCH_WAIT)
	# Launch testing client script
	@echo "Run test client outside of the Enclave ..."
	python3 redis_test.py $(SERVICE_ADDR) $(SERVICE_PORT)
	# Kill the running instance of the server before exit.
	sleep $(SHUTDOWN_WAIT)
	test -f $(APP_NAME).pid && kill -9 `cat $(APP_NAME).pid` && rm $(APP_NAME).pid || true

gdb: clean package
	@ echo -e "\n------start debugging Redis server------\n"
	$(MYST_GDB) --args myst/bin/$(APPNAME) $(OPTS)

$(APPDIR):
	$(APPBUILDER) -d Dockerfile

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	rm -rf rootfs $(APPDIR) myst private.pem $(APP_NAME).pid
