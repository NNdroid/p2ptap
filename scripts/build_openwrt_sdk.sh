#!/usr/bin/env bash
# OpenWrt Native Official SDK Package Builder for p2ptap & luci-app-p2ptap
set -e

SDK_VERSION="${SDK_VERSION:-23.05.5}"
ARCH="${ARCH:-x86-64}"
TARGET="${TARGET:-x86/64}"

echo "========================================================="
echo " Building p2ptap OpenWrt Package using Official OpenWrt SDK"
echo " Target Architecture: ${TARGET} (SDK Version: ${SDK_VERSION})"
echo "========================================================="

# 1. Download official OpenWrt SDK if not present
SDK_DIR="openwrt-sdk-${SDK_VERSION}-${ARCH}"
if [ ! -d "${SDK_DIR}" ]; then
    SDK_URL="https://downloads.openwrt.org/releases/${SDK_VERSION}/targets/${TARGET}/openwrt-sdk-${SDK_VERSION}-${ARCH}_gcc-12.3.0_musl.Linux-x86_64.tar.xz"
    echo "[+] Downloading OpenWrt SDK from ${SDK_URL}..."
    wget -q "${SDK_URL}" -O sdk.tar.xz || curl -sSL "${SDK_URL}" -o sdk.tar.xz
    tar -xf sdk.tar.xz
    rm sdk.tar.xz
    mv openwrt-sdk-* "${SDK_DIR}"
fi

cd "${SDK_DIR}"

# 2. Update and install feeds (golang and luci)
echo "[+] Updating feeds..."
./scripts/feeds update -a >/dev/null
./scripts/feeds install -a >/dev/null

# 3. Copy p2ptap package Makefiles into SDK package/
echo "[+] Copying p2ptap packages into SDK..."
cp -r ../openwrt/package/p2ptap package/
cp -r ../openwrt/package/luci-app-p2ptap package/

# 3.5 Auto compute PKG_MIRROR_HASH
echo "[+] Auto computing source PKG_MIRROR_HASH..."
make package/p2ptap/download >/dev/null 2>&1 || true
COMPUTED_HASH=$(sha256sum dl/p2ptap-*.tar.xz 2>/dev/null | head -n1 | awk '{print $1}')
if [ -n "$COMPUTED_HASH" ]; then
    echo "[+] Auto set PKG_MIRROR_HASH: ${COMPUTED_HASH}"
    sed -i "s/PKG_MIRROR_HASH:=.*/PKG_MIRROR_HASH:=${COMPUTED_HASH}/" package/p2ptap/Makefile
fi

# 4. Compile packages natively using OpenWrt buildroot
echo "[+] Compiling p2ptap..."
make package/p2ptap/compile V=s
echo "[+] Compiling luci-app-p2ptap..."
make package/luci-app-p2ptap/compile V=s

echo "========================================================="
echo " Build Completed Successfully!"
echo " IPK Packages generated in: ${SDK_DIR}/bin/packages/"
echo "========================================================="
