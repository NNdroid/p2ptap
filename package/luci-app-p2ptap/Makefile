include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for p2ptap Layer-2 P2P TAP VPN
LUCI_DEPENDS:=+p2ptap +luci-compat
LUCI_PKGARCH:=all

PKG_NAME:=luci-app-p2ptap
PKG_VERSION:=1.0.20261001
# SDKs without a Git checkout receive this value through the build scripts.
P2PTAP_PKG_RELEASE?=$(shell git rev-list --count HEAD 2>/dev/null)
PKG_RELEASE:=43
# Translation packages must follow the app release, not SDK Git timestamps.
PKG_PO_VERSION:=$(PKG_VERSION)-r$(PKG_RELEASE)

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - signature for the OpenWrt package metadata scanner.
# luci.mk performs the actual build calls, including translation packages.
