#!/bin/bash
#
# diy-part2.sh —— 在 feeds update 之后、feeds install 之前执行
#
# 1) 打开内核每流统计: CONFIG_NET_AIROHA_FLOW_STATS=y
#    （对应 airoha_ppe_foe_flow_stats_* / FLOW_CLS_STATS，硬件卸载的每流 packets/bytes 才会回填）
# 2) argon 主题 v3.1.1 —— 见 diy-part3.sh
# 3) luci-app-airoha-npu (luanmuc)：NPU/CPU/FrameEngine/PPE 状态面板
# 4) OAF 最新版 (destan19/OpenAppFilter)：kmod-oaf + appfilter + luci-app-oaf
# 5) mosdns v5 的 LuCI 界面 (sbwml/luci-app-mosdns) + geo2txt
# 6) 去除 dummy 接口：base-files 里的 dummy device 段直接删掉（kmod-dummy 也不选）
# 7) 断言 PON / 2.5G 驱动包真的存在
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
# 2) argon 主题 v3.1.1 —— 移到 diy-part3.sh（feeds install 之后）执行
#    原因: feeds 里自带同名 luci-theme-argon，若在 install 之前删掉 feeds 目录，
#          feeds install 会留下悬空链接/报错；反过来在 install 之后覆盖最干净。
########################################

########################################
# 3) luci-app-airoha-npu
########################################
echo "==== [diy-part2] luci-app-airoha-npu (luanmuc) ===="
rm -rf package/luci-app-airoha-npu
git clone --depth 1 https://github.com/luanmuc/luci-app-airoha-npu package/luci-app-airoha-npu
if [ -f package/luci-app-airoha-npu/Makefile ]; then
  # 该 Makefile 里硬编码 include $(TOPDIR)/feeds/luci/luci.mk，此处确认路径存在
  if [ -f feeds/luci/luci.mk ]; then
    echo "    ✅ feeds/luci/luci.mk 存在，插件可直接 include"
  else
    echo "    ❌ 缺少 feeds/luci/luci.mk，插件无法构建"; exit 1
  fi
  echo "    ✅ 已就位: $(grep -m1 '^PKG_VERSION' package/luci-app-airoha-npu/Makefile)"
  # 该插件用 devmem 读 FrameEngine/PLL 寄存器，busybox 必须带 devmem applet
  echo "    依赖 busybox devmem（.config 中 CONFIG_BUSYBOX_DEFAULT_DEVMEM=y）"
else
  echo "    ❌ 克隆失败"; exit 1
fi

########################################
# 3.5) OAF（destan19/OpenAppFilter，最新 master）
#      ponwrt 的 feeds 里没有 OAF，必须自己拉。三个包：
#        oaf/            -> kmod-oaf   （netfilter 模块）
#        open-app-filter -> appfilter  （oafd 用户态守护进程）
#        luci-app-oaf    -> LuCI 界面（依赖 luci-compat / luci-lib-jsonc）
########################################
echo "==== [diy-part2] OAF (OpenAppFilter) ===="
OAF_REPO=https://github.com/destan19/OpenAppFilter.git
rm -rf /tmp/oafsrc package/oaf package/open-app-filter package/luci-app-oaf
git clone --depth 1 "$OAF_REPO" /tmp/oafsrc
for p in oaf open-app-filter luci-app-oaf; do
  if [ -f "/tmp/oafsrc/$p/Makefile" ]; then
    cp -a "/tmp/oafsrc/$p" "package/$p"
    echo "    ✅ package/$p ($(grep -m1 '^PKG_VERSION' /tmp/oafsrc/$p/Makefile || echo 'kmod'))"
  else
    echo "    ❌ 上游缺少目录 $p"; exit 1
  fi
done
rm -rf /tmp/oafsrc

########################################
# 3.6) mosdns v5 + LuCI 界面
#      mosdns 本体用 feeds 里的 net/mosdns（5.3.x，即 v5 系列）；
#      LuCI 界面 sbwml/luci-app-mosdns 不在任何 feed 里，单独拉；
#      它依赖 geo2txt（C 工具，解 v2ray geosite/geoip）一并拉。
########################################
echo "==== [diy-part2] mosdns v5 LuCI ===="
MOSDNS_LUCI_REPO=https://github.com/sbwml/luci-app-mosdns.git
rm -rf /tmp/mosdns-luci package/luci-app-mosdns package/geo2txt
git clone --depth 1 "$MOSDNS_LUCI_REPO" /tmp/mosdns-luci
for p in luci-app-mosdns geo2txt; do
  if [ -f "/tmp/mosdns-luci/$p/Makefile" ]; then
    cp -a "/tmp/mosdns-luci/$p" "package/$p"
    echo "    ✅ package/$p ($(grep -m1 '^PKG_VERSION' /tmp/mosdns-luci/$p/Makefile))"
  else
    echo "    ❌ 上游缺少目录 $p"; exit 1
  fi
done
rm -rf /tmp/mosdns-luci

########################################
# 4) 去除 dummy 接口
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

echo "==== [diy-part2] 关键包存在性检查 (feeds 已 update) ===="
chk() { [ -d "$1" ] && echo "    ✅ $1" || echo "    ❌ 缺少 $1"; }
chk feeds/pon_drivers/airoha-xpon
chk feeds/pon_drivers/airoha-pon-frontends
chk feeds/pon_userspace/luci-app-onu
chk feeds/pon_userspace/luci-app-pon-status
chk feeds/pon_userspace/airoha-pon-daemons
chk package/luci-app-airoha-npu
chk package/oaf
chk package/open-app-filter
chk package/luci-app-oaf
chk package/luci-app-mosdns
chk package/geo2txt
chk feeds/packages/net/mosdns

echo "==== [diy-part2] 完成 ===="
