.PHONY: all package $(APPDIR) private.pem

TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER    = $(TOP)/scripts/appbuilder
APPDIR        = appdir
APP_NAME      = redis-server
SERVICE_ADDR  = localhost
SERVICE_PORT  = 6379
TIMEOUT       = 60s

ifdef STRACE
OPTS += --strace
endif

ifdef PERF
OPTS += --perf
endif

all: init package

init: 
	pip3 install redis 

package: init $(APPDIR) private.pem
	cp redis.conf $(APPDIR)/etc/redis.conf
	echo "\n\nport $(SERVICE_PORT)" >> $(APPDIR)/etc/redis.conf
	$(MYST) package-sgx $(APPDIR) private.pem config.json

_run: package
	# This is running in ramfs mode
	# Kill the server from a previous run if it wasn't shut down properly.
	./kill.sh
	
	# Launch the Redis Server
	@ echo -e "\n------starting Redis server------\n"
	myst/bin/$(APP_NAME) $(OPTS) & echo $$! > $(APP_NAME).pid
	timeout $(TIMEOUT) ./wait.sh $(SERVICE_PORT)
	
	# Launch testing client script
	@echo "Run test client outside of the Enclave ..."
	bash -c "time python3 redis_test.py $(SERVICE_ADDR) $(SERVICE_PORT)"
	
	# Kill the running instance of the server before exit.
	./kill.sh

run:
	$(RUNTEST) make -C $(CURDIR) _run

gdb: clean package
	@ echo -e "\n------start debugging Redis server------\n"
	$(MYST_GDB) --args myst/bin/$(APPNAME) $(OPTS)

$(APPDIR):
	$(APPBUILDER) -m -d Dockerfile

private.pem:
	openssl genrsa -out private.pem -3 3072

clean:
	rm -rf rootfs $(APPDIR) myst private.pem $(APP_NAME).pid

ROOTDIR=$(CURDIR)/appdir

native-server:
	./kill.sh
	sudo chroot $(ROOTDIR) /usr/local/bin/redis-server &
	./wait.sh $(SERVICE_PORT)

native: native-server
	bash -c "time python3 redis_test.py $(SERVICE_ADDR) $(SERVICE_PORT)"
	./kill.sh

ns:
	sudo chroot $(ROOTDIR) /usr/local/bin/redis-server &

ds:
	docker run --network=host redis:6.2-alpine /usr/local/bin/redis-server &

ext2-server: rootfs
	./kill.sh
	@ echo -e "\n------starting Redis server------\n"
	$(MYST_EXEC) rootfs /usr/local/bin/redis-server $(OPTS) & echo $$! > $(APP_NAME).pid
	./wait.sh $(SERVICE_PORT)

ext2: ext2-server
	@echo "Run test client outside of the Enclave ..."
	bash -c "time python3 redis_test.py $(SERVICE_ADDR) $(SERVICE_PORT)"
	./kill.sh

rootfs:
	$(MYST) mkext2 appdir rootfs

bench:
	redis-benchmark -q -h 127.0.0.1 -p 6379 -c 5 -n 10000
	./kill.sh

bench-linux:
	$(MAKE) linux
	./wait.sh $(SERVICE_PORT)
	$(MAKE) bench

bench-sgx:
	$(MAKE) sgx
	./wait.sh $(SERVICE_PORT)
	$(MAKE) bench

linux:
	make TARGET=linux ext2-server

sgx:
	make ext2-server

kill:
	./kill.sh

perf: 
	./perf.sh 0 0 7
