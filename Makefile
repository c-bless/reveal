BASEDIR     = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

TMP_DIR      = $(BASEDIR)/tmp
REVEAL_SRC = $(BASEDIR)/reveal
WEBAPP_SRC  = $(REVEAL_SRC)/webapp
WEBAPI_SRC  = $(REVEAL_SRC)/webapi
STATIC_DIR   = $(BASEDIR)/data-directories/static


DOCKER_WEBAPP                   = $(BASEDIR)/services/web
DOCKER_WEBAPP_SRC               = $(BASEDIR)/services/web/reveal
REPORT_DIR                      = $(BASEDIR)/data-directories/reports
DOCKER_REPORT_DIR               = $(BASEDIR)/services/web/reports
UPLOAD_DIR                      = $(BASEDIR)/data-directories/uploads
DOCKER_UPLOAD_DIR               = $(BASEDIR)/services/web/uploads
UPDATE_DATA_DIR                 = $(BASEDIR)/data-directories/update-data
DOCKER_UPDATE_DATA_DIR          = $(BASEDIR)/services/web/update-data
DOCKER_WEB_STATIC_DATA_DIR      = $(BASEDIR)/services/web/static
CONFIGREVIEW_DIR                = $(BASEDIR)/data-directories/configreview_checks
DOCKER_CONFIGREVIEW_DIR         = $(BASEDIR)/services/web/configreview_checks

DOCKER_NGINX_STATIC_DATA_DIR    = $(BASEDIR)/services/nginx/static
DOCKER_NGINX                    = $(BASEDIR)/services/nginx

DOCKER_WEBAPI                   = $(BASEDIR)/services/api
DOCKER_WEBAPI_SRC               = $(BASEDIR)/services/api/reveal


# Check if docker compose (v2) is available
ifeq ($(shell docker compose version 2>/dev/null),)
  DOCKER_COMPOSE := docker-compose
else
  DOCKER_COMPOSE := docker compose
endif


# all targets are commands, not files (otherwise e.g. "tmp" is skipped because the directory tmp/ exists)
.PHONY: tmp help clean fix-permissions build run stop init-db clear-data reset-admin

tmp:
	@$(shell mkdir -p $(UPLOAD_DIR) )
	@$(shell mkdir -p $(STATIC_DIR) )
	./download-dependencies.sh


help:
	@echo
	@echo tmp          	: download dependencies
	@echo build         : build docker container
	@echo fix-permissions : reset ownership of directories created as root by docker
	@echo clean		    : cleanup temporary directories
	@echo run		    : start docker container
	@echo stop		    : stop docker container and drives
	@echo init-db	    : create user "admin" and import EoL dates
	@echo clear-data    : remove all imported data (keep user accounts)


clean:
	@$(shell rm -r $(TMP_DIR))
	@$(shell rm -r $(DOCKER_WEBAPP_SRC))
	@$(shell rm -r $(DOCKER_REPORT_DIR))
	@$(shell rm -r $(DOCKER_UPLOAD_DIR))
	@$(shell rm -r $(DOCKER_UPDATE_DATA_DIR))
	@$(shell rm -r $(DOCKER_CONFIGREVIEW_DIR))
	@$(shell rm -r $(DOCKER_WEB_STATIC_DATA_DIR))
	@$(shell rm -r $(DOCKER_NGINX_STATIC_DATA_DIR))
	@$(shell rm -r $(DOCKER_WEBAPI_SRC))


# Docker creates missing mount points (e.g. for named volumes inside the ./services/web bind mount) as root. This
# breaks the cp commands in "build". The ownership is reset via a container, so no sudo is needed.
fix-permissions:
	docker run --rm -v "$(DOCKER_WEBAPP):/data" alpine:3 sh -c 'for d in update-data uploads reports; do if [ -e "/data/$$d" ]; then chown -R $(shell id -u):$(shell id -g) "/data/$$d"; fi; done'

# The static files are replaced (not merged), so no outdated libraries (e.g. AdminLTE 3 plugins) remain in the images.
build: tmp fix-permissions
	@$(shell cp -r $(REPORT_DIR) $(DOCKER_WEBAPP))
	@$(shell cp -r $(UPLOAD_DIR) $(DOCKER_WEBAPP))
	@$(shell cp -r $(CONFIGREVIEW_DIR) $(DOCKER_WEBAPP))
	mkdir -p $(DOCKER_UPDATE_DATA_DIR)
	cp -r $(UPDATE_DATA_DIR)/. $(DOCKER_UPDATE_DATA_DIR)/
	rm -rf $(DOCKER_WEB_STATIC_DATA_DIR) $(DOCKER_NGINX_STATIC_DATA_DIR)
	cp -r $(STATIC_DIR) $(DOCKER_WEB_STATIC_DATA_DIR)
	cp -r $(STATIC_DIR) $(DOCKER_NGINX_STATIC_DATA_DIR)
	@$(shell cp -r $(REVEAL_SRC) $(DOCKER_WEBAPP))
	@$(shell cp -r $(REVEAL_SRC) $(DOCKER_WEBAPI))
	$(DOCKER_COMPOSE) build

run:
	$(DOCKER_COMPOSE) up

stop:
	$(DOCKER_COMPOSE) down -v

# The EoL CSV is passed via stdin, so the import does not depend on files copied into the container / volumes.
init-db:
	$(DOCKER_COMPOSE) exec -T webapp flask -e webapp.env user create admin
	$(DOCKER_COMPOSE) exec -T webapp flask -e webapp.env import eol /dev/stdin < "$(UPDATE_DATA_DIR)/win-support-dates.csv"

clear-data:
	$(DOCKER_COMPOSE) exec webapp flask -e webapp.env db clear

reset-admin:
	$(DOCKER_COMPOSE) exec webapp flask -e webapp.env user reset admin
