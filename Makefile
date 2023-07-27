BASEDIR     = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
TMPDIR      = $(BASEDIR)/tmp/

SYSTEMDB_SRC="$(BASEDIR)/systemdb/"
WEBAPP_SRC  = $(SYSTEMDB_SRC)/webapp/
WEBAPI_SRC  = $(SYSTEMDB_SRC)/webapi/
STATIC_DIR   = $(BASEDIR)/data-directories/static/
DISTDIR     = $(STATIC_DIR)dist/
PLUGINDIR   = $(STATIC_DIR)plugins/

DOCKER_WEBAPP                   = $(BASEDIR)/services/web/
DOCKER_WEBAPP_SRC               = $(BASEDIR)/services/web/systemdb/
REPORT_DIR                      = $(BASEDIR)/data-directories/reports/
DOCKER_REPORT_DIR               = $(BASEDIR)/services/web/reports/
UPLOAD_DIR                      = $(BASEDIR)/data-directories/uploads/
DOCKER_UPLOAD_DIR               = $(BASEDIR)/services/web/uploads/
UPDATE_DATA_DIR                 = $(BASEDIR)/data-directories/update-data/
DOCKER_UPDATE_DATA_DIR          = $(BASEDIR)/services/web/update-data/
DOCKER_WEB_STATIC_DATA_DIR      = $(BASEDIR)/services/web/static/
DOCKER_NGINX_STATIC_DATA_DIR      = $(BASEDIR)/services/nginx/static/

DOCKER_WEBAPI           = $(BASEDIR)/services/api/
DOCKER_WEBAPI_SRC       = $(BASEDIR)/services/api/systemdb/

help:
	@echo
	@echo all           : download dependencies and build docker container
	@echo build         : build docker container
	@echo clean		    : cleanup temporary directory "tmp"

deps:
	@echo $(BASEDIR)
	@echo $(WEBAPP_SRC)
	@echo $(PLUGINDIR)
	./download-dependencies.sh

clean:
	$(shell rm -r $(TMPDIR)))

build:
	@$(shell cp -r $(REPORT_DIR) $(DOCKER_REPORT_DIR))
	@$(shell cp -r $(UPLOAD_DIR) $(DOCKER_UPLOAD_DIR))
	@$(shell cp -r $(UPDATE_DATA_DIR) $(DOCKER_UPDATE_DATA_DIR))
	@$(shell cp -r $(STATIC_DIR) $(DOCKER_WEB_STATIC_DATA_DIR))
	@$(shell cp -r $(STATIC_DIR) $(DOCKER_NGINX_STATIC_DATA_DIR))
	@$(shell cp -r $(SYSTEMDB_SRC) $(DOCKER_WEBAPP))
	@$(shell cp -r $(SYSTEMDB_SRC) $(DOCKER_WEBAPI))
	@$(shell cp -r $(SYSTEMDB_SRC) $(DOCKER_WEBAPI))
	docker-compose build

run:
	docker-compose up

stop:
	docker-compose down -v

init-db:
	docker-compose exec webapp flask -e webapp.env user create admin
	docker-compose exec webapp flask -e webapp.env import eol "/app/update-data/win-support-dates.csv"

clear-data:
	docker-compose exec webapp flask -e webapp.env db clear

reset-admin:
	docker-compose exec webapp flask -e webapp.env user reset-pw admin