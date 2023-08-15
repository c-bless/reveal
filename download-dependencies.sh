#!/bin/bash


BASEDIR=$(pwd)

TMPDIR="${BASEDIR}/tmp/"
STATIC_DIR="${BASEDIR}/data-directories/static"


TMP_ADMIN_LTE_URL = "https://github.com/ColorlibHQ/AdminLTE/archive/refs/tags/v3.2.0.zip"
TMP_ADMIN_LTE_ZIP = "admin-lte.zip"
TMP_ADMIN_LTE_DIR = "AdminLTE-3.2.0"


echo "[*] Downloading static dependencies"
echo "[*] - AdminLTE"

cd $TMPDIR
wget -O "admin-lte.zip" "https://github.com/ColorlibHQ/AdminLTE/archive/refs/tags/v3.2.0.zip"
unzip "admin-lte.zip" -d $TMPDIR

cd AdminLTE*
cp -r "dist" $STATIC_DIR
cp -r "plugins" $STATIC_DIR

cd $STATIC_DIR
wget -O "swagger-ui.min.css" "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.3.2/swagger-ui.min.css"
wget -O "swagger-ui-bundle.min.js" "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.3.2/swagger-ui-bundle.min.js"
wget -O "swagger-ui-standalone-preset.min.js" "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.3.2/swagger-ui-standalone-preset.min.js"
