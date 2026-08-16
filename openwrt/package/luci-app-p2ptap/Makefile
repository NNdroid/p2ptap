include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for p2ptap Layer-2 P2P TAP VPN
LUCI_DEPENDS:=+p2ptap
LUCI_PKGARCH:=all

PKG_NAME:=luci-app-p2ptap
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(TOPDIR)/feeds/luci/luci.mk

$(eval $(call BuildPackage,luci-app-p2ptap))
