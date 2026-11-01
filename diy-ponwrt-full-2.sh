#!/bin/bash
#
# diy-ponwrt-full-2.sh —— 在 feeds update 之后、feeds install 之前执行
#
# 执行时机很关键（参考 Actions-OpenWrt-S20P 的做法）:
#   - 必须在 feeds update -a 之后: 否则 packages feed 会把 lang/golang 目录重新拉回覆盖
#   - 必须在 feeds install -a 之前: 否则删掉源码树里的 OAF/mosdns 会留下 package/feeds 下的旧链接
#
# 本脚本做 9 件事:
#   1) 打开内核每流统计 CONFIG_NET_AIROHA_FLOW_STATS=y
#   2) 检查 kmod-nf-conntrack-bridge（L2 桥接加速前置）
#   3) Go 工具链换成 sbwml/packages_lang_golang 最新分支（默认 27.x = Go 1.27.3）
#   4) 清理源码/feeds 里自带的 mosdns、v2ray-geodata
#   5) 删除源码/feeds 里自带的 OAF，重新拉 destan19/OpenAppFilter 最新版
#   6) luci-app-airoha-npu (luanmuc)：NPU/CPU/FrameEngine/PPE 状态面板
#   7) mosdns v5（sbwml/luci-app-mosdns v5，含本体 + LuCI + geo2txt）
#   8) 去除 dummy 接口
#   9) 断言 PON / 光模块 / 2.5G / 插件目录都在
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

########################################
# 1) 内核: 每流流量统计
########################################
echo "==== [diy-part2] 打开 CONFIG_NET_AIROHA_FLOW_STATS ===="
KC=target/linux/airoha/an7581/config-6.18
if [ -f "$KC" ]; then
  # 原文件里是 "# CONFIG_NET_AIROHA_FLOW_STATS is not set"
  sed -i 's/^# CONFIG_NET_AIROHA_FLOW_STATS is not set$/CONFIG_NET_AIROHA_FLOW_STATS=y/' "$KC"
  # 若原来没有这一行（上游改名/移动），直接追加
  grep -q '^CONFIG_NET_AIROHA_FLOW_STATS=' "$KC" || echo 'CONFIG_NET_AIROHA_FLOW_STATS=y' >> "$KC"
  if grep -q '^CONFIG_NET_AIROHA_FLOW_STATS=y' "$KC"; then
    echo "    ✅ $KC 已打开每流统计"
    grep -nE '^CONFIG_NET_AIROHA(_FLOW_STATS)?=' "$KC" | sed 's/^/       /'
  else
    echo "    ❌ 改写失败: $KC"; exit 1
  fi
else
  echo "    ❌ 未找到 $KC"; exit 1
fi

# 硬件加速链路必需的 conntrack bridge 支持（an7581 target.mk 已默认带，这里做兜底断言）
echo "==== [diy-part2] 检查 kmod-nf-conntrack-bridge 是否在默认包 ===="
if grep -q 'kmod-nf-conntrack-bridge' target/linux/airoha/an7581/target.mk; then
  echo "    ✅ target.mk DEFAULT_PACKAGES 已含 kmod-nf-conntrack-bridge"
else
  echo "    ⚠️  target.mk 未含 kmod-nf-conntrack-bridge，由 .config 显式选中"
fi

########################################
# 2) Go 工具链: 换成最新版本
#    immortalwrt/packages 里的 lang/golang 版本偏旧，mosdns 5.3.x 需要较新的 Go。
#    换成 sbwml/packages_lang_golang（26.x/27.x 分支持续跟进上游），
#    顺序: 27.x -> 26.x -> 25.x 逐级回退，保证不会因为分支改名整体失败。
########################################
echo "==== [diy-full-p2] 替换 Go 工具链为最新版 ===="
GO_REPO=https://github.com/sbwml/packages_lang_golang
GO_DIR=feeds/packages/lang/golang
GO_TMP=/tmp/golang-src
GO_BRANCH=""
rm -rf "$GO_TMP"
for b in 27.x 26.x 25.x; do
  rm -rf "$GO_TMP"
  if git clone --depth 1 -b "$b" "$GO_REPO" "$GO_TMP" 2>/dev/null; then
    GO_BRANCH="$b"
    break
  fi
  echo "    ⚠️  $b 分支拉取失败，尝试下一个"
done
if [ -z "$GO_BRANCH" ]; then
  echo "    ❌ Go 工具链替换失败（三个分支都拉不下来）"; exit 1
fi
# 布局兼容: 上游 packages 仓库是 Makefile 与 golang-package.mk 同级；
# sbwml 仓库根放 *.mk + golang-build.sh，包的 Makefile 在 golang/ 子目录。
# 整个仓库原样铺到 lang/golang 下，两种布局都能被 buildroot 扫到。
rm -rf "$GO_DIR"
mkdir -p "$GO_DIR"
cp -a "$GO_TMP"/. "$GO_DIR"/
rm -rf "$GO_TMP"
GO_MK=""
for c in "$GO_DIR/Makefile" "$GO_DIR/golang/Makefile"; do
  if [ -f "$c" ]; then GO_MK="$c"; break; fi
done
if [ -z "$GO_MK" ] || [ ! -f "$GO_DIR/golang-package.mk" ]; then
  echo "    ❌ Go 工具链布局异常（Makefile: ${GO_MK:-缺失}）"; exit 1
fi
GO_VER=$(grep -m1 '^PKG_VERSION' "$GO_MK" | cut -d= -f2 | tr -d ' ')
GO_MM=$(grep -m1 '^GO_VERSION_MAJOR_MINOR' "$GO_MK" | cut -d= -f2 | tr -d ' ')
echo "    ✅ 分支 $GO_BRANCH / Go $GO_VER (${GO_MM}) / Makefile: $GO_MK"

########################################
# 3) 清理源码/feeds 里自带的 mosdns、v2ray-geodata
#    它们的包名与下面 sbwml 的版本重名，同时存在会导致 duplicate package。
########################################
echo "==== [diy-part2] 清理源码自带的 mosdns / v2ray-geodata ===="
for d in feeds/packages/net/mosdns \
         feeds/packages/net/v2ray-geodata \
         package/feeds/packages/mosdns \
         package/feeds/packages/v2ray-geodata \
         package/mosdns \
         package/v2ray-geodata; do
  if [ -e "$d" ]; then rm -rf "$d"; echo "    已删除 $d"; fi
done
# 兜底: 任何位置残留的同名 Makefile 一并清掉（跳过 .git）
find package feeds -path '*/.git' -prune -o -type f -name Makefile -print 2>/dev/null \
  | grep -E '/(mosdns|v2ray-geodata)/Makefile$' \
  | while read -r f; do
      rm -rf "$(dirname "$f")"
      echo "    已删除 $(dirname "$f")"
    done || true
echo "    ✅ 清理完成"

########################################
# 4) OAF: 先删掉源码里自带的，再重新拉最新
#    ponwrt 主树本身不含 OAF（官方 configs 里的 kmod-oaf/appfilter 是历史残留），
#    但 feeds / 旧分支可能带一份旧版；用户态与内核模块版本不匹配会 insmod 失败，
#    所以统一“先删干净再拉 master”。三个包:
#      oaf/            -> kmod-oaf   （netfilter 内核模块）
#      open-app-filter -> appfilter  （oafd 用户态守护进程）
#      luci-app-oaf    -> LuCI 界面（依赖 luci-compat / luci-lib-jsonc）
########################################
echo "==== [diy-part2] OAF: 删除自带源码并重新拉取最新版 ===="
# 4.1 删掉 package/ 与 feeds/ 下所有同名目录（含 feeds install 留下的链接）
find package feeds -maxdepth 5 -path '*/.git' -prune -o -type d \
  \( -name "OpenAppFilter" -o -name "open-app-filter" -o -name "luci-app-oaf" -o -name "oaf" \) \
  -print 2>/dev/null | while read -r d; do
    rm -rf "$d"; echo "    已删除 $d"
  done || true
rm -rf package/feeds/*/luci-app-oaf package/feeds/*/OpenAppFilter package/feeds/*/open-app-filter 2>/dev/null || true

# 4.2 重新拉取
OAF_REPO=https://github.com/destan19/OpenAppFilter.git
rm -rf /tmp/oafsrc
if ! git clone --depth 1 "$OAF_REPO" /tmp/oafsrc; then
  echo "    ❌ OAF 克隆失败"; exit 1
fi
for p in oaf open-app-filter luci-app-oaf; do
  if [ -f "/tmp/oafsrc/$p/Makefile" ]; then
    cp -a "/tmp/oafsrc/$p" "package/$p"
    echo "    ✅ package/$p ($(grep -m1 '^PKG_VERSION' /tmp/oafsrc/$p/Makefile || echo 'kmod'))"
  else
    echo "    ❌ 上游缺少目录 $p"; exit 1
  fi
done
OAF_REV=$(git -C /tmp/oafsrc log -1 --format='%h %ad' --date=short)
echo "    OAF 上游版本: $OAF_REV"
rm -rf /tmp/oafsrc

########################################
# 5) luci-app-airoha-npu (luanmuc)
########################################
echo "==== [diy-part2] luci-app-airoha-npu (luanmuc) ===="
rm -rf package/luci-app-airoha-npu
git clone --depth 1 https://github.com/luanmuc/luci-app-airoha-npu package/luci-app-airoha-npu
if [ -f package/luci-app-airoha-npu/Makefile ]; then
  if [ -f feeds/luci/luci.mk ]; then
    echo "    ✅ feeds/luci/luci.mk 存在，插件可直接 include"
  else
    echo "    ❌ 缺少 feeds/luci/luci.mk，插件无法构建"; exit 1
  fi
  echo "    ✅ 已就位: $(grep -m1 '^PKG_VERSION' package/luci-app-airoha-npu/Makefile)"
  echo "    依赖 busybox devmem（.config 中 CONFIG_BUSYBOX_DEFAULT_DEVMEM=y）"
else
  echo "    ❌ 克隆失败"; exit 1
fi

########################################
# 6) mosdns v5: 整仓克隆（本体 + LuCI + geo2txt）
#    sbwml/luci-app-mosdns 的 v5 分支里有三个子目录:
#      mosdns/          -> 本体 5.3.x（v5）
#      luci-app-mosdns/ -> LuCI 界面
#      geo2txt/         -> 解析 v2ray geosite/geoip 的 C 工具
#    直接放到 package/mosdns，OpenWrt 会递归发现子目录里的 Makefile。
########################################
echo "==== [diy-part2] mosdns v5 (sbwml/luci-app-mosdns) ===="
MOSDNS_REPO=https://github.com/sbwml/luci-app-mosdns.git
rm -rf package/mosdns
if ! git clone --depth 1 -b v5 "$MOSDNS_REPO" package/mosdns; then
  echo "    ❌ mosdns 克隆失败"; exit 1
fi
for p in mosdns luci-app-mosdns geo2txt; do
  if [ -f "package/mosdns/$p/Makefile" ]; then
    echo "    ✅ package/mosdns/$p ($(grep -m1 '^PKG_VERSION' "package/mosdns/$p/Makefile"))"
  else
    echo "    ❌ 上游缺少 package/mosdns/$p/Makefile"; exit 1
  fi
done

echo "==== [diy-part2] v2ray-geodata (sbwml) ===="
rm -rf package/v2ray-geodata
if git clone --depth 1 https://github.com/sbwml/v2ray-geodata package/v2ray-geodata; then
  echo "    ✅ package/v2ray-geodata ($(grep -m1 '^PKG_VERSION' package/v2ray-geodata/Makefile 2>/dev/null || echo 'ok'))"
else
  echo "    ❌ v2ray-geodata 克隆失败"; exit 1
fi

########################################
# 7) 去除 dummy 接口
########################################
echo "==== [diy-part2] 去除 dummy 接口 ===="
# 目标板上 dummy0 通常来自 base-files 的 network 模板（config device 'dummy0'），
# 打包前直接从模板里删掉，避免首启被 netifd 创建；kmod-dummy 也不在 .config 里选中。
clean_dummy() {
  f="$1"
  [ -f "$f" ] || return 0
  if ! grep -qi 'dummy' "$f"; then
    echo "    无 dummy: $f"
    return 0
  fi
  awk 'BEGIN { RS=""; ORS="\n\n" } !/[[:space:]]option[[:space:]]+name[[:space:]]+.dummy/' "$f" > "$f.tmp"
  mv "$f.tmp" "$f"
  if grep -qi 'dummy' "$f"; then
    echo "    ⚠️  仍有 dummy 残留（非 device 段写法）: $f"
    grep -n -i dummy "$f" | sed 's/^/       /'
  else
    echo "    ✅ 已清理: $f"
  fi
}
clean_dummy package/base-files/files/etc/config/network
for f in target/linux/airoha/base-files/etc/config/network \
         target/linux/airoha/an7581/base-files/etc/config/network; do
  clean_dummy "$f"
done

########################################
# 8) 关键包存在性检查 (feeds 已 update)
########################################
echo "==== [diy-part2] 关键包存在性检查 ===="
fail=0
chk() { if [ -d "$1" ]; then echo "    ✅ $1"; else echo "    ❌ 缺少 $1"; fail=1; fi; }
# PON / 光模块驱动（feeds 提供；kmod-airoha-en7572 在 airoha-pon-frontends 里定义）
chk feeds/pon_drivers/airoha-xpon
chk feeds/pon_drivers/airoha-pon-frontends
# ONU 用户态
chk feeds/pon_userspace/luci-app-onu
chk feeds/pon_userspace/luci-app-pon-status
chk feeds/pon_userspace/airoha-pon-daemons
# 本脚本拉取的
chk package/oaf
chk package/open-app-filter
chk package/luci-app-oaf
chk package/mosdns/mosdns
chk package/mosdns/luci-app-mosdns
chk package/mosdns/geo2txt
chk package/v2ray-geodata
chk package/luci-app-airoha-npu
chk feeds/packages/lang/golang
if [ "$fail" = "1" ]; then echo "❌ 有包缺失，终止"; exit 1; fi
echo "    ✅ 全部就位"

echo "==== [diy-part2] 完成 ===="
