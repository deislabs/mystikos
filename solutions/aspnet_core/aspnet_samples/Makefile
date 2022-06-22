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
	$(MAKE) run-podcast-with-retry
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

run-podcast-with-retry:
	./run_podcast_with_retry.sh

run-podcast:
	@echo "Running podcast sample"
	./kill.sh Podcast
	$(MAKE) kill-db

	@echo "Starting DB"
	$(MAKE) run-db

	@echo "Starting Podcast server"
	timeout 120s $(MYST_EXEC) $(OPTS) --app-config-path config-podcast.json rootfs /built/dotnet-podcasts/Podcast.API &
	timeout 30s ./wait.sh

	@echo "Starting Podcast client"
	./client.sh Podcast

	@echo "Clean up"
	./kill.sh Podcast
	$(MAKE) kill-db

# This is used by Podcast sample
run-db:
	docker run --name dotnet-podcast-db -e "ACCEPT_EULA=Y" -e "SA_PASSWORD=Pass@word" -p 5433:1433 -d mcr.microsoft.com/mssql/server:2019-CU8-ubuntu-18.04
	sleep 10

kill-db:
	docker rm -f dotnet-podcast-db
