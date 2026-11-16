# OpenWrt package definition for luci-app-oaf-lite.
#
# 在本仓库里这个包只负责「把 C 采样器编译成 /usr/bin/oaf-lite」：
# init.d / config / uci-defaults / LuCI 页面 / 静态资源都由仓库根目录的
# files/ 叠加层提供（workflow 会 cp -a files/. openwrt/files/），避免同一份
# 文件在 package 与 files/ 里各存一份、改一处漏一处。
#
# 需要自包含的 .ipk（含页面与配置）时用 oaf-lite 项目里的同名 Makefile。
#
#   make package/luci-app-oaf-lite/compile V=s
#
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-oaf-lite
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-or-later

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-oaf-lite
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=User List (lightweight L7 sampler)
  DEPENDS:=+luci-base +luci-compat +luci-lib-jsonc +libuci-lua +lua +libpthread +conntrack
  CONFLICTS:=luci-app-oaf
endef

define Package/luci-app-oaf-lite/description
  User list / client detail pages from Actions-OpenWrt-ponwrt, backed by a
  self-contained C sampler instead of oaf.ko/oafd. Reads the OAF plaintext
  feature library for app names, samples the first packets of each flow for
  TLS/HTTP/QUIC/DNS/FAILED/OTHER, and accounts bytes through conntrack so
  hardware-offloaded (MTK closed HNAT / Airoha AN7581 PPE) traffic is counted.
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CROSS= \
		CFLAGS="$(TARGET_CFLAGS) -O2 -Wall -Wextra -std=gnu99 -D_GNU_SOURCE" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/luci-app-oaf-lite/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/oaf-lite $(1)/usr/bin/oaf-lite
endef

define Package/luci-app-oaf-lite/postinst
#!/bin/sh
# 首启/升级后让新菜单生效；服务本身由 /etc/init.d/oaf-lite（files/ 叠加层）提供
rm -f /tmp/luci-indexcache* 2>/dev/null
[ -x /etc/init.d/oaf-lite ] && /etc/init.d/oaf-lite enable
exit 0
endef

$(eval $(call BuildPackage,luci-app-oaf-lite))
