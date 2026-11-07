include $(TOPDIR)/rules.mk

PKG_NAME:=p2ptap
PKG_VERSION:=1.0.20261107.297
# Keep the complete upstream version in the binary; APK metadata is numeric.
P2PTAP_VERSION:=v1.0.20261107.297-c7d5161
P2PTAP_GIT_COMMIT:=c7d51610c79c47d6e5ea7cc62c63e46b6dc6b01c
# SDKs without a Git checkout receive this value through the build scripts.
P2PTAP_PKG_RELEASE?=$(shell git rev-list --count HEAD 2>/dev/null)
PKG_RELEASE:=297

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/NNdroid/p2ptap.git
PKG_SOURCE_VERSION:=c7d51610c79c47d6e5ea7cc62c63e46b6dc6b01c
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
GO_PKG_LDFLAGS:=-s -w -X p2ptap/pkg/version.Version=$(P2PTAP_VERSION) -X p2ptap/pkg/version.BuildTime=unknown -X p2ptap/pkg/version.GitCommit=$(P2PTAP_GIT_COMMIT)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

# Match the project's portable release builds; TAP and networking use pure Go.
GO_PKG_TARGET_VARS += CGO_ENABLED=0
GO_PKG_DEFAULT_LDFLAGS:=

# pkg/go-libp2p is intentionally NOT versioned (see patches/go-libp2p/README.md):
# go.mod wires the patched fork in with
#   replace github.com/libp2p/go-libp2p v0.50.0 => ./pkg/go-libp2p
# so a source tree fetched via PKG_SOURCE_PROTO=git cannot ever carry it —
# materialising it in the CI workspace does not help the SDK, which re-fetches
# the source itself. Prepare therefore materialises the pinned upstream tag plus
# the local patch inside $(PKG_BUILD_DIR), exactly like the Go CI's
# setup-libp2p composite action. The tree already contains the fetch script and
# the patch; the step needs git + network on the build host, which the source
# download itself already requires. Idempotent: an already-materialised tree
# (local SDK build) short-circuits with "already present".
define Build/Prepare
	$(call Build/Prepare/Default)
	# Build/Prepare commands run from the package directory, not
	# $(PKG_BUILD_DIR); the script anchors on its own location, so an absolute
	# path materialises into the right tree. Invoke via bash: the archive's
	# exec bit is not reliable across checkouts.
	bash $(PKG_BUILD_DIR)/scripts/fetch-libp2p.sh
endef

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
