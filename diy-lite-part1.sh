#!/bin/bash
#
# diy-lite-part1.sh —— 纯净版: 在 feeds update 之前执行（改 feeds.conf.default）
#
# 纯净版只动一处 feeds:
#   pon_userspace -> naoki66/OpenWrt_ONU_CONFIG
#   该仓库是 pbs05/openwrt-pon-userspace 的深度 fork，把 luci-app-pon 升级为
#   luci-app-onu，并附 luci-app-pon-status。纯净版保留它，是因为
#   "把光口注册上去" 属于基础功能，不是可选插件；仓库里的 files-lite/etc/config/pon
#   也是按这套 UCI 结构写的。
#   （若想连它也去掉、只留纯上游 luci-app-pon，删掉下面这段替换即可。）
#
# pon_drivers 保持 pbs05 官方源（xpon MAC + 光前端 EN7572/GN28L95/UX3363）。
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

echo "==== [diy-lite-p1] 替换 pon_userspace feed -> naoki66/OpenWrt_ONU_CONFIG ===="
if grep -q '^src-git pon_userspace' feeds.conf.default; then
  sed -i "s#^src-git pon_userspace.*#src-git pon_userspace ${ONU_FEED}#" feeds.conf.default
  echo "    已替换: $(grep '^src-git pon_userspace' feeds.conf.default)"
else
  echo "src-git pon_userspace ${ONU_FEED}" >> feeds.conf.default
  echo "    已追加: $(grep '^src-git pon_userspace' feeds.conf.default)"
fi

echo "==== [diy-lite-p1] 确保 pon_drivers feed 存在 ===="
if ! grep -q '^src-git pon_drivers' feeds.conf.default; then
  echo 'src-git pon_drivers https://github.com/pbs05/openwrt-pon-drivers.git' >> feeds.conf.default
  echo "    已追加 pon_drivers"
else
  echo "    已存在: $(grep '^src-git pon_drivers' feeds.conf.default)"
fi

echo "==== [diy-lite-p1] 当前 feeds ===="
grep -vE '^\s*#|^\s*$' feeds.conf.default
echo "==== [diy-lite-p1] 完成 ===="
