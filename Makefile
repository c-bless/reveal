BASEDIR     = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
TMPDIR      = $(BASEDIR)/tmp/

SYSTEMDB_SRC="$(BASEDIR)/systemdb/"
WEBAPP_SRC  = $(SYSTEMDB_SRC)/webapp/
WEBAPI_SRC  = $(SYSTEMDB_SRC)/webapi/
STATICDIR   = $(WEBAPP_SRC)/systemdb/web/static/
DISTDIR     = $(STATICDIR)dist/
PLUGINDIR   = $(STATICDIR)plugins/

DOCKER_WEBAPP           = $(BASEDIR)/services/web/
DOCKER_WEBAPP_SRC       = $(BASEDIR)/services/web/systemdb/
REPORT_DIR              = $(BASEDIR)/reports/
DOCKER_REPORT_DIR       = $(BASEDIR)/services/web/reports/
UPLOAD_DIR              = $(BASEDIR)/uploads/
DOCKER_UPLOAD_DIR       = $(BASEDIR)/services/web/uploads/
UPDATE_DATA_DIR         = $(BASEDIR)/update-data/
DOCKER_UPDATE_DATA_DIR  = $(BASEDIR)/services/web/update-data/

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
	$(shell ./download-dependencies.sh)

clean:
	$(shell rm -r $(TMPDIR)))

build:
	@$(shell cp -r $(REPORT_DIR) $(DOCKER_REPORT_DIR))
	@$(shell cp -r $(UPLOAD_DIR) $(DOCKER_UPLOAD_DIR))
	@$(shell cp -r $(UPDATE_DATA_DIR) $(DOCKER_UPDATE_DATA_DIR))
	@$(shell cp -r $(SYSTEMDB_SRC) $(DOCKER_WEBAPP))
	@$(shell cp -r $(SYSTEMDB_SRC) $(DOCKER_WEBAPI))
	docker-compose build

init-db:
	docker-compose exec webapp flask -e webapp.env user create admin
	docker-compose exec webapp flask -e webapp.env import eol "/app/update-data/win-support-dates.csv"


