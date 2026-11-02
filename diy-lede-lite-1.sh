#!/bin/bash
#
# diy-lede-lite-1.sh —— 纯净版(LEDE 源码): 在 feeds update 之前执行
#
# LEDE(coolsnowwolf/lede) 的 feeds.conf.default 里没有 PON 相关源，
# 所以这里【追加】两个 feed（不是替换，LEDE 自带的 packages/luci/... 保持不动）:
#   pon_drivers  -> pbs05/openwrt-pon-drivers    （xPON MAC + 光前端 EN7572 等）
#   pon_userspace-> naoki66/OpenWrt_ONU_CONFIG   （luci-app-onu / luci-app-pon-status / pond / ponctl）
#
set -e

PON_DRIVERS=https://github.com/pbs05/openwrt-pon-drivers.git
ONU_FEED=https://github.com/naoki66/OpenWrt_ONU_CONFIG.git

# 定位源码树：脚本可能被从仓库根或 openwrt/ 内调用，统一进 openwrt/
cd "$(dirname "$0")"
if [ -f feeds.conf.default ] && [ -d scripts ]; then
  :
elif [ -f openwrt/feeds.conf.default ]; then
  cd openwrt
else
  echo "❌ 找不到 openwrt/LEDE 源码树 (feeds.conf.default)"; exit 1
fi
echo "当前目录: $(pwd)"

add_feed() {
  name="$1"; url="$2"
  if grep -q "^src-git $name " feeds.conf.default; then
    sed -i "s#^src-git $name .*#src-git $name ${url}#" feeds.conf.default
    echo "    已更新: $(grep "^src-git $name " feeds.conf.default)"
  else
    echo "src-git $name ${url}" >> feeds.conf.default
    echo "    已追加: $(grep "^src-git $name " feeds.conf.default)"
  fi
}

echo "==== [diy-lede-lite-p1] 追加 PON 相关 feeds ===="
add_feed pon_drivers "$PON_DRIVERS"
add_feed pon_userspace "$ONU_FEED"

########################################
# 关闭 helloworld feed
#   LEDE 的 feeds.conf.default 默认启用 helloworld (fw876/helloworld)，
#   里面就是 luci-app-ssr-plus / passwall / openclash / bypass / vssr 这些代理插件。
#   纯净版不需要，直接注释掉：feeds update/install 就不会再克隆、安装它们，
#   既省 clone 时间和磁盘（runner 只有 73G，编译期会写满），
#   也让「默认包里写了 luci-app-ssr-plus」这种情况彻底不可能出现。
########################################
echo "==== [diy-lede-lite-p1] 关闭 helloworld feed（第三方代理插件来源）===="
if grep -qE '^src-git helloworld ' feeds.conf.default; then
  sed -i 's|^src-git helloworld |#src-git helloworld |' feeds.conf.default
  echo "    已注释: $(grep -E '^#src-git helloworld ' feeds.conf.default)"
elif grep -qE '^#\s*src-git helloworld ' feeds.conf.default; then
  echo "    已是注释状态: $(grep -E '^#\s*src-git helloworld ' feeds.conf.default)"
else
  echo "    ℹ️  feeds.conf.default 里没有 helloworld 条目，跳过"
fi
if grep -qE '^\s*src-git helloworld ' feeds.conf.default; then
  echo "    ❌ helloworld feed 仍处于启用状态"; exit 1
fi

echo "==== [diy-lede-lite-p1] 当前 feeds ===="
grep -vE '^\s*#|^\s*$' feeds.conf.default
echo "==== [diy-lede-lite-p1] 完成 ===="
