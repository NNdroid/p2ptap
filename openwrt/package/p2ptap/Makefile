include $(TOPDIR)/rules.mk

PKG_NAME:=p2ptap
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/NNdroid/p2ptap.git
PKG_SOURCE_VERSION:=main
PKG_MIRROR_HASH:=519831f130ddb58f234a252c1e5593e308429de9bc2be39f4152342121d95bf1

PKG_MAINTAINER:=p2ptap developers
PKG_LICENSE:=MIT

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

GO_PKG:=p2ptap
GO_PKG_BUILD_PKG:=p2ptap/cmd/p2ptap
GO_PKG_LDFLAGS:=-s -w -X p2ptap/pkg/version.Version=$(PKG_VERSION) -X p2ptap/pkg/version.BuildTime=unknown -X p2ptap/pkg/version.GitCommit=unknown

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/p2ptap
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=go-libp2p Layer-2 P2P TAP VPN
  URL:=https://github.com/NNdroid/p2ptap
  DEPENDS:=$(GO_ARCH_DEPENDS) +kmod-tun +ca-certificates
endef

define Package/p2ptap/description
  p2ptap is a high-performance Layer-2 P2P TAP Virtual Private Network built on go-libp2p.
  It supports multi-transport (QUIC, WebRTC, WebTransport, TCP), obfuscation padding,
  PSK authentication, and NAT traversal with Circuit Relay v2.
endef

define Package/p2ptap/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/p2ptap $(1)/usr/bin/p2ptap

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/p2ptap.config $(1)/etc/config/p2ptap

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/p2ptap.init $(1)/etc/init.d/p2ptap
endef

$(eval $(call BuildPackage,p2ptap))
