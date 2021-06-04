TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
ROOTFS=hello_server.cpio

ifdef STRACE
OPTS = --strace
endif

all: rootfs

rootfs: appdir
	$(MYST) mkcpio appdir $(ROOTFS)

appdir:
	$(APPBUILDER) Dockerfile

run:
	test -f server.pid && kill -9 `cat server.pid` || true
	@echo "=== starting flask server ==="
	@$(MYST_EXEC) $(OPTS) $(ROOTFS) /usr/local/bin/python3 /app/flask_app.py & echo $$! > server.pid
	@sleep 10
	curl 127.0.0.1:8000 -w "\n"
	@echo "=== stopping flask server ==="
	@test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true
	@echo "=== starting uwsgi server ==="
	@$(MYST_EXEC) $(OPTS) $(ROOTFS) /usr/local/bin/uwsgi /app/uwsgi.ini & echo $$! > server.pid
	@sleep 10
	curl 127.0.0.1:8000 -w "\n"
	@echo "=== stopping flask server ==="
	@test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true

server-flask:
	$(MYST_EXEC) $(OPTS) $(ROOTFS) /usr/local/bin/python3 /app/flask_app.py

server-uwsgi:
	$(MYST_EXEC) $(OPTS) $(ROOTFS) /usr/local/bin/uwsgi /app/uwsgi.ini

clean:
	test -f server.pid && kill -9 `cat server.pid` || true
	rm -rf $(ROOTFS) appdir server.pid
