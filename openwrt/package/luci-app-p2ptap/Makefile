include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for p2ptap Layer-2 P2P TAP VPN
LUCI_DEPENDS:=+p2ptap +luci-compat
LUCI_PKGARCH:=all

PKG_NAME:=luci-app-p2ptap
PKG_VERSION:=1.0.0
# SDKs without a Git checkout receive this value through the build scripts.
P2PTAP_PKG_RELEASE?=$(shell git rev-list --count HEAD 2>/dev/null)
PKG_RELEASE:=$(if $(P2PTAP_PKG_RELEASE),$(P2PTAP_PKG_RELEASE),1)
# Translation packages must follow the app release, not SDK Git timestamps.
PKG_PO_VERSION:=$(PKG_VERSION)-r$(PKG_RELEASE)

include $(TOPDIR)/feeds/luci/luci.mk
