TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS += --strace
endif

TIMEOUT=30s
TOP_TIMEOUT=240s

build: rootfs

appdir:
	$(APPBUILDER) -m Dockerfile

rootfs: appdir
	$(MYST) mkext2 appdir rootfs

clean: kill-db
	./kill.sh FlightFinder
	./kill.sh Todo
	./kill.sh Podcast
	rm -rf appdir rootfs client.output

_run:
	# Disable for now as run-db step can be sometimes unstable
	# See commit message for more error details
	# $(MAKE) run-podcast
	$(MAKE) run-flight
	$(MAKE) run-todo

run:
	TIMEOUT=$(TOP_TIMEOUT) $(RUNTEST) make -C $(CURDIR) _run

run-flight:
	echo "Running FlightFinder sample"
	./kill.sh FlightFinder
	timeout $(TIMEOUT) $(MYST_EXEC) $(OPTS) --app-config-path config-flight.json rootfs /usr/bin/dotnet /built/FlightFinder/FlightFinder.Server.dll &
	timeout $(TIMEOUT) ./wait.sh
	./client.sh FlightFinder
	./kill.sh FlightFinder
	test -f client.output

run-todo:
	echo "Running Todo sample"
	./kill.sh Todo
	timeout $(TIMEOUT) $(MYST_EXEC) $(OPTS) --app-config-path config-todo.json rootfs /built/TodoApi/TodoApi &
	timeout $(TIMEOUT) ./wait.sh
	./client.sh Todo
	./kill.sh Todo

run-podcast:
	echo "Running podcast sample"
	$(MAKE) kill-db
	$(MAKE) run-podcast-inner
	$(MAKE) kill-db

run-podcast-inner: run-db
	./kill.sh Podcast
	timeout 120s $(MYST_EXEC) $(OPTS) --app-config-path config-podcast.json rootfs /built/dotnet-podcasts/Podcast.API &
	timeout $(TIMEOUT) ./wait.sh
	./client.sh Podcast
	./kill.sh Podcast

# This is used by Podcast sample
run-db:
	docker run --name dotnet-podcast-db -e "ACCEPT_EULA=Y" -e "SA_PASSWORD=Pass@word" -p 5433:1433 -d mcr.microsoft.com/mssql/server:2019-CU8-ubuntu-18.04 && sleep 5s

kill-db:
	docker rm -f dotnet-podcast-db
