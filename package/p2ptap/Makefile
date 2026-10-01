include $(TOPDIR)/rules.mk

PKG_NAME:=p2ptap
PKG_VERSION:=1.0.20261001
# SDKs without a Git checkout receive this value through the build scripts.
P2PTAP_PKG_RELEASE?=$(shell git rev-list --count HEAD 2>/dev/null)
PKG_RELEASE:=43

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/NNdroid/p2ptap.git
PKG_SOURCE_VERSION:=e9b571f9c1ab26f0b540ccec013ff4c02e632ee5
PKG_MIRROR_HASH:=skip

PKG_MAINTAINER:=p2ptap developers
PKG_LICENSE:=MIT

PKG_BUILD_DEPENDS:=golang1.27/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

GO_PKG:=p2ptap
# Preserve embedded WebUI assets and the local libp2p module replacement.
GO_PKG_INSTALL_ALL:=1
GO_PKG_BUILD_PKG:=p2ptap/cmd/p2ptap
GO_PKG_LDFLAGS:=-s -w -X p2ptap/pkg/version.Version=$(PKG_VERSION) -X p2ptap/pkg/version.BuildTime=unknown -X p2ptap/pkg/version.GitCommit=unknown

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

# Match the project's portable release builds; TAP and networking use pure Go.
GO_PKG_TARGET_VARS += CGO_ENABLED=0
GO_PKG_DEFAULT_LDFLAGS:=

define Package/p2ptap
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=go-libp2p Layer-2 P2P TAP VPN
  URL:=https://github.com/NNdroid/p2ptap
  DEPENDS:=$(GO_ARCH_DEPENDS) +kmod-tun +ca-certificates +libubox +jshn
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
