#!/bin/bash
#
# diy-lite-part2.sh —— 纯净版(桥接版): 在 feeds update 之后、feeds install 之前执行
#
# 纯净版不引用仓库里的 files/ 覆盖层（不带实机 PPPoE 账号、不带个人密码、不带 UPnP 配置），
# 所有默认值都在构建期直接写进源码树，等价于"固件出厂状态"。
#
# 本脚本做 6 件事（不 clone 任何第三方插件）:
#   1) 打开内核每流统计 CONFIG_NET_AIROHA_FLOW_STATS=y
#      （PPE 的 airoha_ppe_foe_flow_stats_* / FLOW_CLS_STATS 依赖它，否则计数恒 0）
#   2) 断言 L2 桥接卸载前置 kmod-nf-conntrack-bridge 在默认包里
#   3) 从 base-files / target 的 network 模板里删掉 dummy 段
#   4) 生成首启 uci-defaults: 默认打开 flow_offloading(含硬件) + dummy 兜底清理
#   5) 默认 root 密码设为 admin123
#   6) 断言 PON / 光模块 / ONU 用户态包目录都在
#
set -e

ROOT_PASS="${ROOT_PASS:-admin123}"

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
# 1) 内核: 每流流量统计（硬件加速的计数来源）
########################################
echo "==== [diy-lite-p2] 打开 CONFIG_NET_AIROHA_FLOW_STATS ===="
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

########################################
# 2) L2 桥接卸载前置（an7581 target.mk 默认带，这里做兜底断言）
########################################
echo "==== [diy-lite-p2] 检查 kmod-nf-conntrack-bridge 是否在默认包 ===="
if grep -q 'kmod-nf-conntrack-bridge' target/linux/airoha/an7581/target.mk; then
  echo "    ✅ target.mk DEFAULT_PACKAGES 已含 kmod-nf-conntrack-bridge"
else
  echo "    ⚠️  target.mk 未含 kmod-nf-conntrack-bridge，由 .config-lite 显式选中"
fi

########################################
# 3) 去除 dummy 接口
########################################
echo "==== [diy-lite-p2] 去除 dummy 接口 ===="
# 目标板上 dummy0 通常来自 base-files 的 network 模板（config device 'dummy0'），
# 打包前直接从模板里删掉，避免首启被 netifd 创建；kmod-dummy 也不在 .config-lite 里选中。
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
# 4) 首启默认值: 桥接加速（生成 uci-defaults，不依赖仓库 files/）
########################################
echo "==== [diy-lite-p2] 生成首启默认值 uci-defaults ===="
UD_DIR=package/base-files/files/etc/uci-defaults
mkdir -p "$UD_DIR"
cat > "$UD_DIR/99-lite-bridge" <<'EOF'
#!/bin/sh
# PonWrt 纯净版(桥接版) 首启默认值 —— 由构建脚本生成，不在仓库里保存实机配置
# 幂等：重复执行无副作用

# 1) 硬件加速: fw4 会为 inet 与 bridge 各生成一张 flowtable，
#    L3(路由/NAT) 与 L2(桥接 lan<->lan) 都下到 Airoha PPE；
#    flow_offloading_hw=1 才会把 flowtable 标记 offload 并下发。
uci -q set firewall.@defaults[0].flow_offloading='1'
uci -q set firewall.@defaults[0].flow_offloading_hw='1'
uci -q commit firewall

# 2) dummy 接口兜底清理（模板已清理，这里处理升级上来的残留）
for s in $(uci -q show network 2>/dev/null | sed -n "s/^network\.\([^.=]*\)\.name='dummy[^']*'$/\1/p"); do
	uci -q delete network."$s"
done
for s in $(uci -q show network 2>/dev/null | sed -n "s/^network\.\([^.=]*\)\.ifname='dummy[^']*'$/\1/p"); do
	uci -q delete network."$s"
done
uci -q commit network 2>/dev/null

# 3) 主题固定内置 bootstrap
if uci -q get luci.main >/dev/null 2>&1; then
	uci -q set luci.main.mediaurlbase='/luci-static/bootstrap'
	uci -q commit luci
fi

# 4) 让 fw4 重新生成规则（含 bridge flowtable）
/etc/init.d/firewall reload >/dev/null 2>&1

exit 0
EOF
chmod 755 "$UD_DIR/99-lite-bridge"
echo "    ✅ 已生成 $UD_DIR/99-lite-bridge（flow_offloading / flow_offloading_hw 默认开）"

########################################
# 5) 默认 root 密码
########################################
echo "==== [diy-lite-p2] 设置默认 root 密码 ===="
SHADOW=package/base-files/files/etc/shadow
[ -f "$SHADOW" ] || { echo "    ❌ 缺少 $SHADOW"; exit 1; }

# 优先 sha256-crypt($5$)，失败则退回 md5-crypt($1$)
HASH=""
if command -v openssl >/dev/null 2>&1; then
  HASH=$(openssl passwd -5 "$ROOT_PASS" 2>/dev/null || true)
  [ -n "$HASH" ] || HASH=$(openssl passwd -1 "$ROOT_PASS" 2>/dev/null || true)
fi
if [ -z "$HASH" ]; then
  echo "    ❌ 无法生成密码哈希（openssl 不可用）"; exit 1
fi

# 只替换 root 行的第 2 字段，其余字段与其它账号原样保留
if grep -q '^root:' "$SHADOW"; then
  awk -F: -v h="$HASH" 'BEGIN{OFS=":"} $1=="root" && !d {$2=h; d=1} {print}' "$SHADOW" > "$SHADOW.new"
  mv "$SHADOW.new" "$SHADOW"
else
  printf 'root:%s:0:0:99999:7:::\n' "$HASH" >> "$SHADOW"
fi
rm -f "$SHADOW.new"
echo "    ✅ root 密码已设为 ${ROOT_PASS}（$(printf '%s' "$HASH" | cut -c1-3) 哈希）"
grep -m1 '^root:' "$SHADOW" | sed 's/^/       /'

########################################
# 6) 关键包存在性检查（feeds 已 update）
########################################
echo "==== [diy-lite-p2] 关键包存在性检查 ===="
fail=0
chk() { if [ -d "$1" ]; then echo "    ✅ $1"; else echo "    ❌ 缺少 $1"; fail=1; fi; }
# PON / 光模块驱动（feeds 提供；kmod-airoha-en7572 在 airoha-pon-frontends 里定义）
chk feeds/pon_drivers/airoha-xpon
chk feeds/pon_drivers/airoha-pon-frontends
# ONU 用户态
chk feeds/pon_userspace/luci-app-onu
chk feeds/pon_userspace/luci-app-pon-status
chk feeds/pon_userspace/airoha-pon-daemons
if [ "$fail" = "1" ]; then echo "❌ 有包缺失，终止"; exit 1; fi
echo "    ✅ 全部就位"

echo "==== [diy-lite-p2] 完成（纯净版未拉取任何第三方插件、未引用仓库 files/）===="
