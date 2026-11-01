#!/bin/bash
#
# diy-part1.sh —— 在 feeds update 之前执行（改 feeds.conf.default）
#
# 做两件事:
#   1) pon_userspace 换成 naoki66/OpenWrt_ONU_CONFIG
#      该仓库是 pbs05/openwrt-pon-userspace 的深度 fork：把 luci-app-pon 升级为顶级
#      luci-app-onu，并吸收 luci-app-iptv，新增 internet/voice 页与 luci-app-pon-status。
#      包名与上游重叠（airoha-pond / airoha-ponctl），所以必须【替换】而非【追加】，
#      否则 feeds install 会因同名包冲突失败。
#   2) pon_drivers 保持 pbs05 官方源（xpon MAC + 光前端 EN7572/GN28L95/UX3363）。
#
set -e

ONU_FEED=https://github.com/naoki66/OpenWrt_ONU_CONFIG.git

# 定位源码树：脚本可能被从仓库根或 openwrt/ 内调用，统一进 openwrt/
cd "$(dirname "$0")"
if [ -f feeds.conf.default ] && [ -d scripts ]; then
  :
elif [ -f openwrt/feeds.conf.default ]; then
  cd openwrt
else
  echo "❌ 找不到 openwrt 源码树 (feeds.conf.default)"; exit 1
fi
echo "当前目录: $(pwd)"

echo "==== [diy-part1] 替换 pon_userspace feed -> naoki66/OpenWrt_ONU_CONFIG ===="
if grep -q '^src-git pon_userspace' feeds.conf.default; then
  sed -i "s#^src-git pon_userspace.*#src-git pon_userspace ${ONU_FEED}#" feeds.conf.default
  echo "    已替换: $(grep '^src-git pon_userspace' feeds.conf.default)"
else
  echo "src-git pon_userspace ${ONU_FEED}" >> feeds.conf.default
  echo "    已追加: $(grep '^src-git pon_userspace' feeds.conf.default)"
fi

echo "==== [diy-part1] 确保 pon_drivers feed 存在 ===="
if ! grep -q '^src-git pon_drivers' feeds.conf.default; then
  echo 'src-git pon_drivers https://github.com/pbs05/openwrt-pon-drivers.git' >> feeds.conf.default
  echo "    已追加 pon_drivers"
else
  echo "    已存在: $(grep '^src-git pon_drivers' feeds.conf.default)"
fi

echo "==== [diy-part1] 当前 feeds ===="
grep -vE '^\s*#|^\s*$' feeds.conf.default
echo "==== [diy-part1] 完成 ===="
