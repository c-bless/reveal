#!/bin/sh


BASEDIR=$(pwd)

TMPDIR="${BASEDIR}/tmp/"

SYSTEMDB_SRC="${BASEDIR}/systemdb/"
WEBAPP_SRC="${SYSTEMDB_SRC}webapp/"
STATICDIR="${WEBAPP_SRC}web/static/"
DISTDIR="${STATICDIR}dist/"
PLUGINDIR="${STATICDIR}plugins/"


mkdir tmp 
echo "[*] Downloading static dependencies"

echo "[*] - AdminLTE"
cd $TMPDIR
mkdir "admin-lte"
wget -O admin-lte.zip https://github.com/ColorlibHQ/AdminLTE/archive/refs/tags/v3.2.0.zip 
unzip admin-lte.zip -d "admin-lte"
cd admin-lte/Admin*
if [! -d $DISTDIR ]; then
    mkdir $DISTDIR
fi
cp -r "dist/" $DISTDIR
cp -r "plugins" $PLUGINDIR

