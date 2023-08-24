BASEDIR     = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

TMP_DIR      = $(BASEDIR)/tmp
SYSTEMDB_SRC = $(BASEDIR)/systemdb/
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

DOCKER_NGINX_STATIC_DATA_DIR    = $(BASEDIR)/services/nginx/static/
DOCKER_NGINX                    = $(BASEDIR)/services/nginx/

DOCKER_WEBAPI                   = $(BASEDIR)/services/api/
DOCKER_WEBAPI_SRC               = $(BASEDIR)/services/api/systemdb/

TMP_ADMIN_LTE_URL = https://github.com/ColorlibHQ/AdminLTE/archive/refs/tags/v3.2.0.zip
TMP_ADMIN_LTE_ZIP = "admin-lte.zip"
TMP_ADMIN_LTE_DIR = "$(TMP_DIR)/admin-lte"
TMP_ADMIN_LTE_DIST = "$(TMP_DIR)/AdminLTE-3.2.0/dist"
TMP_ADMIN_LTE_PLUGINS = "$(TMP_DIR)/AdminLTE-3.2.0/plugins"


tmp:
	@$(shell mkdir -p $(TMP_ADMIN_LTE_DIR) )
	@$(shell mkdir -p $(UPLOAD_DIR) )
	./download-dependencies.sh


help:
	@echo
	@echo tmp          	: download dependencies
	@echo build         : build docker container
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
	@$(shell rm -r $(DOCKER_WEB_STATIC_DATA_DIR))
	@$(shell rm -r $(DOCKER_NGINX_STATIC_DATA_DIR))
	@$(shell rm -r $(DOCKER_WEBAPI_SRC))


build: tmp
	@$(shell cp -r $(REPORT_DIR) $(DOCKER_WEBAPP))
	@$(shell cp -r $(UPLOAD_DIR) $(DOCKER_WEBAPP))
	@$(shell cp -r $(UPDATE_DATA_DIR) $(DOCKER_WEBAPP))
	@$(shell cp -r $(STATIC_DIR) $(DOCKER_WEBAPP))
	@$(shell cp -r $(STATIC_DIR) $(DOCKER_NGINX))
	@$(shell cp -r $(SYSTEMDB_SRC) $(DOCKER_WEBAPP))
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
	docker-compose exec webapp flask -e webapp.env user reset admin