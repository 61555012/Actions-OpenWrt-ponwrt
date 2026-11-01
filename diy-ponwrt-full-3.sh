#!/bin/bash
#
# diy-ponwrt-full-3.sh —— 在 feeds install -a 之后执行
#
# 做两件事:
#   1) 用 jerrykuku/luci-theme-argon v3.1.1 覆盖 feeds 里自带的旧版 argon
#      （feeds/luci 里那份是 v2 系列，v3 才有自带设置页 luci-app-argon-config.json，
#        以及 ucode 版模板。这里先删 package/feeds 下的软链，再删 feeds 目录，
#        最后把 v3.1.1 克隆到 package/ 下，保证构建时用的是新版。）
#   2) 断言最终 package 目录里 argon 的版本号是 3.x
#
set -e

# 定位源码树：脚本可能被从仓库根或 openwrt/ 内调用，统一进 openwrt/
cd "$(dirname "$0")"
if [ -f feeds.conf.default ] && [ -d scripts ]; then
  echo "已处于源码树根: $(pwd)"
elif [ -f openwrt/feeds.conf.default ]; then
  cd openwrt
  echo "进入源码树: $(pwd)"
else
  echo "❌ 找不到 openwrt 源码树 (feeds.conf.default)"; exit 1
fi

ARGON_REPO=https://github.com/jerrykuku/luci-theme-argon
ARGON_REF=v3.1.1

echo "==== [diy-part3] 清理 feeds install 留下的悬空链接 ===="
# diy-part2 在 feeds install 之前删掉了 mosdns / v2ray-geodata 的 feed 目录，
# feeds 索引里仍有条目，install 时可能生成指向已删除目录的软链；
# 悬空链接会让 OpenWrt 扫描 package/ 时报错，这里统一清掉。
if [ -d package/feeds ]; then
  dangling=$(find package/feeds -maxdepth 3 -xtype l 2>/dev/null | wc -l)
  find package/feeds -maxdepth 3 -xtype l -delete 2>/dev/null || true
  echo "    已清理悬空链接 $dangling 个"
fi
# 同名包去重: 本仓库自己拉的版本优先
for n in mosdns v2ray-geodata luci-app-mosdns; do
  if [ -e "package/$n" ]; then
    rm -rf package/feeds/*/"$n" 2>/dev/null || true
    echo "    已移除 package/feeds/*/$n （使用 package/ 下的自拉版本）"
  fi
done

echo "==== [diy-part3] 覆盖 argon 主题 -> ${ARGON_REF} ===="

# 1) 清掉 feeds install 生成的软链（以及旧版兼容包）
rm -rf package/feeds/luci/luci-theme-argon \
       package/feeds/luci/luci-theme-argon-mod \
       package/feeds/luci/luci-app-argon-config \
       package/luci-theme-argon \
       package/luci-app-argon-config

# 2) 清掉 feeds 里的旧版源码目录，避免后面再被 install 回来
find ./feeds -maxdepth 4 -type d \
  \( -name "luci-theme-argon" -o -name "luci-theme-argon-mod" -o -name "luci-app-argon-config" \) \
  -prune -exec rm -rf {} + 2>/dev/null || true

# 3) 拉新版到 package/
git clone --depth 1 -b "$ARGON_REF" "$ARGON_REPO" package/luci-theme-argon

PKGVER=$(grep -m1 '^PKG_VERSION' package/luci-theme-argon/Makefile | cut -d= -f2 | tr -d ' ')
echo "    argon 版本: ${ARGON_REF} / ${PKGVER}"
case "$PKGVER" in
  3.*) echo "    ✅ 版本校验通过" ;;
  *)   echo "    ❌ 期望 3.x，实际 '${PKGVER}'"; exit 1 ;;
esac

# 4) argon v3 自带设置页（root/usr/share/luci/menu.d/luci-app-argon-config.json），
#    不需要 compat/ 里的空壳包，避免与主题内页面重名。
if [ -f package/luci-theme-argon/root/usr/share/luci/menu.d/luci-app-argon-config.json ]; then
  echo "    ✅ 主题包内已含设置页（无需 luci-app-argon-config 兼容包）"
else
  echo "    ⚠️  未见内置设置页，若需要独立设置页请启用 compat/ 里的兼容包"
fi

# 5) 默认值：居中登录页 + Bing 壁纸（config 与 uci-defaults 都要改，后者会在首启覆盖前者）
ARGON_CFG=package/luci-theme-argon/root/etc/config/argon
ARGON_DEF=package/luci-theme-argon/root/etc/uci-defaults/30_luci-theme-argon
if [ -f "$ARGON_CFG" ]; then
  sed -i \
    -e "s/^\([[:space:]]*option login_style\).*/\1 'centered'/" \
    -e "s/^\([[:space:]]*option online_wallpaper\).*/\1 'bing'/" \
    "$ARGON_CFG"
  echo "    config: $(grep -E 'login_style|online_wallpaper' "$ARGON_CFG" | tr -d '\t\r' | tr '\n' ' ')"
fi
if [ -f "$ARGON_DEF" ]; then
  # 该文件是 CRLF 行尾，去掉 \r 再匹配
  sed -i \
    -e 's/^login_style[[:space:]]\+classic\r\?$/login_style centered/' \
    -e 's/^online_wallpaper[[:space:]]\+none\r\?$/online_wallpaper bing/' \
    "$ARGON_DEF"
  echo "    uci-defaults: $(grep -E '^(login_style|online_wallpaper) ' "$ARGON_DEF" | tr -d '\r' | tr '\n' ' ')"
fi

echo "==== [diy-part3] 完成 ===="
