#!/bin/bash


BASEDIR=$(pwd)

TMPDIR="${BASEDIR}/tmp/"

SYSTEMDB_SRC="${BASEDIR}/systemdb"
WEBAPP_SRC="${SYSTEMDB_SRC}/webapp"
STATICDIR="${BASEDIR}/data-directories/static"


if [! -d $TMPDIR ]; then
    mkdir $TMPDIR
fi

echo "[*] Downloading static dependencies"

echo "[*] - AdminLTE"
cd $TMPDIR
if [! -d "admin-lte" ]; then
    mkdir "admin-lte"
fi
wget -O admin-lte.zip https://github.com/ColorlibHQ/AdminLTE/archive/refs/tags/v3.2.0.zip
unzip admin-lte.zip -d "admin-lte"
cd admin-lte/Admin*

cp -r "dist/" $STATICDIR
cp -r "plugins" $STATICDIR

