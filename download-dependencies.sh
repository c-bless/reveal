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

