#!/bin/bash
# diy-ponwrt-full-1.sh —— feeds update 之前执行，钉住 feeds.conf.default
#
# pon_userspace 用上游 pbs05/openwrt-pon-userspace，不再用 naoki66/OpenWrt_ONU_CONFIG
# 那个 fork（它把 luci-app-pon 换成 luci-app-onu、吸收 luci-app-iptv、自带 wanup 规则）。
# 两个 feed 的包名都与上游重叠，必须改写而非追加，否则 feeds install 同名冲突。
#
set -e

PON_USERSPACE_FEED=https://github.com/pbs05/openwrt-pon-userspace.git
PON_DRIVERS_FEED=https://github.com/pbs05/openwrt-pon-drivers.git

cd "$(dirname "$0")"
if [ -f feeds.conf.default ] && [ -d scripts ]; then
  :
elif [ -f openwrt/feeds.conf.default ]; then
  cd openwrt
else
  echo "❌ 找不到 openwrt 源码树 (feeds.conf.default)"; exit 1
fi
echo "当前目录: $(pwd)"

echo "==== [diy-part1] pon_userspace -> 上游 pbs05/openwrt-pon-userspace ===="
if grep -q '^src-git pon_userspace' feeds.conf.default; then
  sed -i "s#^src-git pon_userspace.*#src-git pon_userspace ${PON_USERSPACE_FEED}#" feeds.conf.default
else
  echo "src-git pon_userspace ${PON_USERSPACE_FEED}" >> feeds.conf.default
fi
echo "    $(grep '^src-git pon_userspace' feeds.conf.default)"

echo "==== [diy-part1] pon_drivers 钉到官方源 ===="
if grep -q '^src-git pon_drivers' feeds.conf.default; then
  sed -i "s#^src-git pon_drivers.*#src-git pon_drivers ${PON_DRIVERS_FEED}#" feeds.conf.default
else
  echo "src-git pon_drivers ${PON_DRIVERS_FEED}" >> feeds.conf.default
fi
echo "    $(grep '^src-git pon_drivers' feeds.conf.default)"

if grep -q 'naoki66/OpenWrt_ONU_CONFIG' feeds.conf.default; then
  echo "❌ feeds.conf.default 里仍指向 naoki66/OpenWrt_ONU_CONFIG"; exit 1
fi

echo "==== [diy-part1] 当前 feeds ===="
grep -vE '^\s*#|^\s*$' feeds.conf.default
echo "==== [diy-part1] 完成 ===="
