#!/bin/bash
#
# diy-lede-lite-2.sh —— 纯净版(LEDE 源码): 在 feeds update 之后、feeds install 之前执行
#
# 与 diy-ponwrt-lite-2.sh 做的事情一致，只是面向 LEDE 源码树（没有官方 an7581 基线 config，
# 所以 LEDE 版的 .config 是最小种子，靠 make defconfig 补齐默认值）:
#   1) 打开内核每流统计 CONFIG_NET_AIROHA_FLOW_STATS=y
#   2) 检查/兜底 L2 桥接卸载前置 kmod-nf-conntrack-bridge（LEDE 默认包里没有，靠 .config-lede-lite 选）
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
  echo "❌ 找不到 openwrt/LEDE 源码树 (feeds.conf.default)"; exit 1
fi

########################################
# 0) 裁剪 LEDE router 默认包 —— 只留拨号 + 基础路由
#
#    LEDE(coolsnowwolf) 的 include/target.mk 里 DEFAULT_PACKAGES.router 自带一堆
#    lean 插件，默认会全部编进固件（这就是之前固件里出现 ssr-plus 等的原因）:
#      luci-app-ssr-plus / luci-app-upnp / luci-app-turboacc / luci-app-ddns /
#      luci-app-vsftpd / luci-app-filetransfer / luci-app-vlmcsd / luci-app-wol /
#      luci-app-arpbind / luci-app-accesscontrol / luci-app-nlbwmon / luci-app-autoreboot /
#      ddns-scripts_aliyun / ddns-scripts_dnspod / coremark /
#      kmod-tun / kmod-ipt-raw / iptables-mod-tproxy / kmod-sched-bpf /
#      kmod-xdp-sockets-diag
#    这些不是 .config 里 "is not set" 就能可靠挡住的（默认 y 由默认包清单注入），
#    所以直接在源码层把这份清单换成白名单，再让 make defconfig 按白名单走。
########################################
echo "==== [diy-lede-lite-p2] 裁剪 LEDE router 默认包（只留拨号 + 基础路由）===="
if ! command -v python3 >/dev/null 2>&1; then
  echo "    ❌ 需要 python3 才能裁剪 include/target.mk"; exit 1
fi
python3 - <<'PY'
import re, sys, pathlib

TARGET_MK = pathlib.Path('include/target.mk')
if not TARGET_MK.is_file():
    print('    ❌ 未找到 include/target.mk'); sys.exit(1)

# 白名单：拨号(PPPoE) + DHCP/DNS + IPv6 + 基础路由 + 防火墙 + LuCI
KEEP = """
dnsmasq-full firewall4 nftables-json iptables ip6tables libip6tc kmod-ipt-nat6
ppp ppp-mod-pppoe odhcp6c odhcpd-ipv6only
ip-full ipset block-mount kmod-nf-nathelper kmod-nf-nathelper-extra iptables-mod-extra
default-settings luci luci-proto-ipv6 luci-proto-ppp
curl ca-certificates kmod-sched-core kmod-veth
""".split()

# 必须从默认包里消失的（第三方插件 / 代理专用）
BAN = """
luci-app-ssr-plus luci-app-passwall luci-app-passwall2 luci-app-openclash
luci-app-bypass luci-app-vssr luci-app-upnp luci-app-turboacc luci-app-ddns
luci-app-vsftpd luci-app-filetransfer luci-app-vlmcsd luci-app-wol
luci-app-arpbind luci-app-accesscontrol luci-app-nlbwmon luci-app-autoreboot
ddns-scripts_aliyun ddns-scripts_dnspod coremark
kmod-tun kmod-ipt-raw iptables-mod-tproxy kmod-sched-bpf kmod-xdp-sockets-diag
""".split()

src = TARGET_MK.read_text()
m = re.search(r'^DEFAULT_PACKAGES\.router:=\\\n(?:.*\\\n)*[^\\\n]*\n', src, re.M)
if not m:
    print('    ❌ 未能在 include/target.mk 中定位 DEFAULT_PACKAGES.router 块'); sys.exit(1)

block = m.group(0)
old = [t for t in block[len('DEFAULT_PACKAGES.router:='):].replace('\\', ' ').split()]
removed = [t for t in old if t not in KEEP]
added = [t for t in KEEP if t not in old]

lines = ['DEFAULT_PACKAGES.router:=\\']
per_line = 6
for i in range(0, len(KEEP), per_line):
    chunk = ' '.join(KEEP[i:i + per_line])
    lines.append('\t' + chunk + (' \\' if i + per_line < len(KEEP) else ''))
new_block = '\n'.join(lines) + '\n'

pathlib.Path('include/target.mk.bak.plugins').write_text(src)
TARGET_MK.write_text(src.replace(block, new_block, 1))

print('    已剔除 %d 项: %s' % (len(removed), ' '.join(removed)))
if added:
    print('    已补入 %d 项: %s' % (len(added), ' '.join(added)))
print('    新 DEFAULT_PACKAGES.router:')
for ln in new_block.strip().split('\n'):
    print('       ' + ln)

left = [b for b in BAN if re.search(r'(?<![\w.-])%s(?![\w.-])' % re.escape(b), TARGET_MK.read_text())]
if left:
    print('    ❌ 仍残留: %s' % ' '.join(left)); sys.exit(1)
print('    ✅ include/target.mk 默认包已白名单化，无第三方插件')
PY

########################################
# 1) 内核: 每流流量统计（硬件加速的计数来源）
########################################
echo "==== [diy-lede-lite-p2] 打开 CONFIG_NET_AIROHA_FLOW_STATS ===="
KC=target/linux/airoha/an7581/config-6.18
if [ -f "$KC" ]; then
  sed -i 's/^# CONFIG_NET_AIROHA_FLOW_STATS is not set$/CONFIG_NET_AIROHA_FLOW_STATS=y/' "$KC"
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
# 2) L2 桥接卸载前置
#    PonWrt/immortalwrt 里有 kmod-nf-conntrack-bridge 这个包；
#    LEDE 没有打包（package/kernel/linux/modules/netfilter.mk 里没有），
#    generic config-6.18 里还是 "is not set"。
#    所以直接把这几个内核符号写成 =y，编进内核镜像：
#      CONFIG_BRIDGE_NETFILTER     —— bridge 上跑 netfilter 的钩子
#      CONFIG_NF_CONNTRACK_BRIDGE  —— bridge family flowtable 生成硬件条目的前提
#      否则 fw4 的 bridge flowtable 只有软件路径，PPE 收不到 L2 流。
########################################
echo "==== [diy-lede-lite-p2] 打开 bridge conntrack（LEDE 无对应 kmod 包）===="
for sym in CONFIG_BRIDGE_NETFILTER CONFIG_NF_CONNTRACK_BRIDGE; do
  sed -i "s/^# ${sym} is not set$/${sym}=y/" "$KC"
  grep -q "^${sym}=" "$KC" || echo "${sym}=y" >> "$KC"
  if grep -q "^${sym}=y" "$KC"; then
    echo "    ✅ ${sym}=y"
  else
    echo "    ❌ ${sym} 未能置为 =y"; exit 1
  fi
done

echo "==== [diy-lede-lite-p2] 检查 kmod-nf-conntrack-bridge ===="
if grep -q 'KernelPackage/nf-conntrack-bridge' package/kernel/linux/modules/netfilter.mk 2>/dev/null; then
  echo "    ℹ️  LEDE 已有 kmod-nf-conntrack-bridge 包，.config 里也可选它"
else
  echo "    ℹ️  LEDE 无 kmod-nf-conntrack-bridge 包，已用内核 =y 方式替代（见上）"
fi

########################################
# 3) 去除 dummy 接口
########################################
echo "==== [diy-lede-lite-p2] 去除 dummy 接口 ===="
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
echo "==== [diy-lede-lite-p2] 生成首启默认值 uci-defaults ===="
UD_DIR=package/base-files/files/etc/uci-defaults
mkdir -p "$UD_DIR"
cat > "$UD_DIR/99-lede-lite-bridge" <<'EOF'
#!/bin/sh
# 040G-MD 纯净版(LEDE 源码) 首启默认值 —— 由构建脚本生成，不在仓库里保存实机配置
# 幂等：重复执行无副作用

# 1) 硬件加速: fw4 为 inet 与 bridge 各生成一张 flowtable，
#    L3(路由/NAT) 与 L2(桥接 lan<->lan) 都下到 Airoha PPE。
uci -q set firewall.@defaults[0].flow_offloading='1'
uci -q set firewall.@defaults[0].flow_offloading_hw='1'
uci -q commit firewall

# 2) dummy 接口兜底清理
for s in $(uci -q show network 2>/dev/null | sed -n "s/^network\.\([^.=]*\)\.name='dummy[^']*'$/\1/p"); do
	uci -q delete network."$s"
done
for s in $(uci -q show network 2>/dev/null | sed -n "s/^network\.\([^.=]*\)\.ifname='dummy[^']*'$/\1/p"); do
	uci -q delete network."$s"
done
uci -q commit network 2>/dev/null

# 3) 主题固定内置 bootstrap（LEDE 默认可能是 argon）
if uci -q get luci.main >/dev/null 2>&1; then
	uci -q set luci.main.mediaurlbase='/luci-static/bootstrap'
	uci -q commit luci
fi

# 4) 让 fw4 重新生成规则（含 bridge flowtable）
/etc/init.d/firewall reload >/dev/null 2>&1

exit 0
EOF
chmod 755 "$UD_DIR/99-lede-lite-bridge"
echo "    ✅ 已生成 $UD_DIR/99-lede-lite-bridge（flow_offloading / flow_offloading_hw 默认开）"

########################################
# 5) 默认 root 密码
########################################
echo "==== [diy-lede-lite-p2] 设置默认 root 密码 ===="
SHADOW=package/base-files/files/etc/shadow
if [ ! -f "$SHADOW" ]; then
  mkdir -p "$(dirname "$SHADOW")"
  : > "$SHADOW"
fi

HASH=""
if command -v openssl >/dev/null 2>&1; then
  HASH=$(openssl passwd -5 "$ROOT_PASS" 2>/dev/null || true)
  [ -n "$HASH" ] || HASH=$(openssl passwd -1 "$ROOT_PASS" 2>/dev/null || true)
fi
if [ -z "$HASH" ]; then
  echo "    ❌ 无法生成密码哈希（openssl 不可用）"; exit 1
fi

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
echo "==== [diy-lede-lite-p2] 关键包存在性检查 ===="
fail=0
chk() { if [ -d "$1" ]; then echo "    ✅ $1"; else echo "    ❌ 缺少 $1"; fail=1; fi; }
chk feeds/pon_drivers/airoha-xpon
chk feeds/pon_drivers/airoha-pon-frontends
chk feeds/pon_userspace/luci-app-onu
chk feeds/pon_userspace/luci-app-pon-status
chk feeds/pon_userspace/airoha-pon-daemons
if [ "$fail" = "1" ]; then echo "❌ 有包缺失，终止"; exit 1; fi
echo "    ✅ 全部就位"

echo "==== [diy-lede-lite-p2] 完成（LEDE 纯净版未拉取任何第三方插件、未引用仓库 files/）===="
