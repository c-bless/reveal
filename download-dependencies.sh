#!/bin/bash
#
# Downloads the static frontend dependencies (AdminLTE 4 + vendor libraries) to data-directories/static.
#
#   data-directories/static/dist/      AdminLTE 4 (CSS/JS)
#   data-directories/static/vendor/    Bootstrap 5, DataTables, JSZip, Font Awesome
#
# AdminLTE 4 does not bundle any plugins anymore (AdminLTE 3 shipped them in "plugins/"). The vendor libraries are
# downloaded as npm packages with pinned versions.

set -euo pipefail

BASEDIR=$(pwd)

TMPDIR="${BASEDIR}/tmp"
STATIC_DIR="${BASEDIR}/data-directories/static"
VENDOR_DIR="${STATIC_DIR}/vendor"

ADMIN_LTE_VERSION="4.10.1"
ADMIN_LTE_URL="https://github.com/ColorlibHQ/AdminLTE/releases/download/v${ADMIN_LTE_VERSION}/admin-lte-v${ADMIN_LTE_VERSION}.zip"

SWAGGER_UI_VERSION="5.3.2"

# npm packages: "<package>@<version> <directories to copy from the package>"
NPM_PACKAGES=(
    "bootstrap@5.3.8 dist/js"
    "datatables.net@3.1.4 js"
    "datatables.net-bs5@3.1.4 js css"
    "datatables.net-buttons@4.1.2 js"
    "datatables.net-buttons-bs5@4.1.2 js css"
    "datatables.net-responsive@4.1.1 js"
    "datatables.net-responsive-bs5@4.1.1 js css"
    "jszip@3.10.2 dist"
    "@fortawesome/fontawesome-free@7.3.1 css webfonts"
)

mkdir -p "${TMPDIR}" "${STATIC_DIR}"

echo "[*] Downloading static dependencies"

# remove old versions (e.g. AdminLTE 3 "plugins") so no outdated files remain
rm -rf "${STATIC_DIR}/dist" "${STATIC_DIR}/plugins" "${VENDOR_DIR}"
mkdir -p "${VENDOR_DIR}"

echo "[*] - AdminLTE ${ADMIN_LTE_VERSION}"
rm -rf "${TMPDIR}/admin-lte" && mkdir -p "${TMPDIR}/admin-lte"
wget -q -O "${TMPDIR}/admin-lte.zip" "${ADMIN_LTE_URL}"
unzip -q "${TMPDIR}/admin-lte.zip" -d "${TMPDIR}/admin-lte"
# the release archive contains the "dist" directory (directly or below a top level directory)
ADMIN_LTE_DIST=$(find "${TMPDIR}/admin-lte" -maxdepth 2 -type d -name dist | head -n 1)
mkdir -p "${STATIC_DIR}/dist"
cp -r "${ADMIN_LTE_DIST}/css" "${ADMIN_LTE_DIST}/js" "${STATIC_DIR}/dist/"
mkdir -p "${STATIC_DIR}/dist/assets"
cp -r "${ADMIN_LTE_DIST}/assets/img" "${STATIC_DIR}/dist/assets/"

for entry in "${NPM_PACKAGES[@]}"; do
    read -r spec dirs <<< "${entry}"
    name="${spec%@*}"
    version="${spec##*@}"
    tarball_name="${name##*/}-${version}.tgz"
    target="${VENDOR_DIR}/${name}"
    echo "[*] - ${name} ${version}"
    rm -rf "${TMPDIR}/npm" && mkdir -p "${TMPDIR}/npm"
    wget -q -O "${TMPDIR}/npm/package.tgz" "https://registry.npmjs.org/${name}/-/${tarball_name}"
    tar -xzf "${TMPDIR}/npm/package.tgz" -C "${TMPDIR}/npm"
    mkdir -p "${target}"
    for d in ${dirs}; do
        mkdir -p "${target}/${d}"
        cp -r "${TMPDIR}/npm/package/${d}/." "${target}/${d}/"
    done
    cp "${TMPDIR}/npm/package/LICENSE"* "${target}/" 2>/dev/null || true
done

echo "[*] - Swagger UI ${SWAGGER_UI_VERSION}"
cd "${STATIC_DIR}"
wget -q -O "swagger-ui.min.css" "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/${SWAGGER_UI_VERSION}/swagger-ui.min.css"
wget -q -O "swagger-ui-bundle.min.js" "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/${SWAGGER_UI_VERSION}/swagger-ui-bundle.min.js"
wget -q -O "swagger-ui-standalone-preset.min.js" "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/${SWAGGER_UI_VERSION}/swagger-ui-standalone-preset.min.js"

echo "[+] Static dependencies downloaded to ${STATIC_DIR}"
