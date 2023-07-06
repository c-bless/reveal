#!/bin/sh

BASEDIR=$(pwd)
APPDIR="${BASEDIR}/systemdb/"
TMPDIR="${BASEDIR}/tmp/"
STATICDIR="${BASEDIR}/systemdb/systemdb/web/static/"
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
cd $BASEDIR

echo "[*] - ReDoc "
#wget -O "redoc.standalone.js" "https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"
cp "redoc.standalone.js" "${STATICDIR}redoc.standalone.js"

echo "[*] - RapiDoc "
#wget -o "rapidoc-min.js" "https://unpkg.com/rapidoc/dist/rapidoc-min.js" 
cp "rapidoc-min.js"  "${STATICDIR}rapidoc-min.js"

echo "[*] - Swagger UI - TODO "


cd $BASEDIR
echo "[*] creating virtual environment in directory "venv" "
python -m venv venv
source venv/bin/activate

echo "[*] Installing python dependencies" 
cd systemdb
pip install --use-pep517 -r requirements.txt

echo "[*] Initializing database and importing EoL dates"
flask import eol "${BASEDIR}/update-data/win-support-dates.csv"

echo "[*] removing temporary data"
rm -r $TMPDIR

echo "[*] Setup completed. You can import and analyze data now! For help visit:"
echo "[*] https://bitbucket.org/cbless/systemdb/src/master/README.md"
