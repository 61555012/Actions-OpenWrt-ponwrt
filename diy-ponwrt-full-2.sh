#!/bin/bash
#
# diy-ponwrt-full-2.sh —— 在 feeds update 之后、feeds install 之前执行
#
# 执行时机很关键（参考 Actions-OpenWrt-S20P 的做法）:
#   - 必须在 feeds update -a 之后: 否则 packages feed 会把上游目录重新拉回覆盖
#   - 必须在 feeds install -a 之前: 内核补丁与 target 配置要在内核解包前写好，
#     install 之后再改会留下不一致的索引/软链
#
# 本脚本做 6 件事:
#   1) 打开内核每流统计 CONFIG_NET_AIROHA_FLOW_STATS=y
#   2) 拉长 PPE 条目在 TCP FIN 之后的老化时间 (1s -> 30s)
#   3) 检查 kmod-nf-conntrack-bridge（L2 桥接加速前置）
#   4) luci-app-airoha-npu (luanmuc)：NPU/CPU/FrameEngine/PPE 状态面板
#   5) 去除 dummy 接口
#   6) 关键包存在性检查 + 删掉 LuCI 里没用的「系统 → 插件」页
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

########################################
# 2) 内核: 拉长 PPE 条目在 TCP FIN 之后的老化时间 (1s -> 30s)
#
# 为什么改（和流量统计是同一件事，不是两件事）:
#   airoha_ppe_hw_init() 给 PPE_BIND_AGE1 写的 delta_tcp_fin 是 1(秒),
#   delta_tcp 是 60(秒)。收到 FIN 的流由硬件按 delta_tcp_fin 老化,
#   也就是"最后一个包之后约 1 秒"条目就从 PPE 表里消失。
#
#   报文一旦下到 PPE, 就不再经过 netfilter, conntrack 里的字节数只能靠驱动
#   定期回写拿到:
#     nf_flow_table → airoha_ppe_flow_offload_cmd(FLOW_CLS_STATS)
#       → airoha_ppe_flow_offload_stats() → airoha_ppe_foe_entry_get_stats()
#       → 读 npu->stats[index] 的增量, 累加进 flow 的 pkts/bytes
#   FLOW_CLS_DESTROY（删条目）只 airoha_ppe_foe_flow_remove_entry(), 不取最后一次计数。
#   所以条目一旦先被硬件回收, 下一次 FLOW_CLS_STATS 轮到这个 hash 时
#   airoha_ppe_foe_get_flow_stats_index() 已经失败, 尾部这一截字节永久丢失。
#   conntrack 累计值是一切按流统计（/proc/net/nf_conntrack、连接数/流量看板）
#   的数据源, 秒级结束的大流量丢得最狠。
#   把 FIN 老化放到 30s, 条目能活到下一次 stats 轮询之后再回收。
#
# 怎么验证打进去了（刷完固件，寄存器是初始化时锁存的，读回来就是实际生效值）:
#   devmem 0x1FB50E40 32   →  0x001E003C  正确（0x1E=30 秒 FIN, 0x3C=60 秒 TCP）
#   devmem 0x1FB50E40 32   →  0x0001003C  说明还是源码默认 1 秒，补丁没进内核
#   注意：运行中用 devmem 写回这个寄存器无效（条目照样 0.5s 内回收），
#   这些 delta 只在 airoha_ppe_hw_init() 里锁存一次，只能改源码重编。
#
# 代价:
#   已结束的连接在 PPE 表里多占 30 秒槽位。表有 16K 槽(4K SRAM + 12K DRAM),
#   家用场景同时在用的流只有几百条, 没有压力; TCP 的常态老化(60s)保持不变。
#
# 写法:
#   往 target/linux/airoha/patches-6.18/ 放一个普通 unified diff,
#   内核解包时由 buildroot 的 quilt 流程自动打上(-p1)。
#   万一上游改动了这段代码导致打不上, 内核 prepare 阶段会直接报错中断,
#   不会静默产出"没改过"的固件。
########################################
echo "==== [diy-part2] 拉长 PPE TCP_FIN 老化时间 (1s -> 30s) ===="
PDIR=target/linux/airoha/patches-6.18
if [ ! -d "$PDIR" ]; then
  echo "    ❌ 未找到 $PDIR（上游内核版本变了？检查目录名）"; exit 1
fi
PFILE="$PDIR/700-net-airoha-ppe-raise-tcp-fin-age.patch"
cat > "$PFILE" <<'PATCH_EOF'
diff --git a/drivers/net/ethernet/airoha/airoha_ppe.c b/drivers/net/ethernet/airoha/airoha_ppe.c
index 8defd19..5266da8 100644
--- a/drivers/net/ethernet/airoha/airoha_ppe.c
+++ b/drivers/net/ethernet/airoha/airoha_ppe.c
@@ -116,7 +116,7 @@ static void airoha_ppe_hw_init(struct airoha_ppe *ppe)
 		airoha_fe_rmw(eth, REG_PPE_BND_AGE1(i),
 			      PPE_BIND_AGE1_DELTA_TCP_FIN |
 			      PPE_BIND_AGE1_DELTA_TCP,
-			      FIELD_PREP(PPE_BIND_AGE1_DELTA_TCP_FIN, 1) |
+			      FIELD_PREP(PPE_BIND_AGE1_DELTA_TCP_FIN, 30) |
 			      FIELD_PREP(PPE_BIND_AGE1_DELTA_TCP, 60));
 
 		airoha_fe_rmw(eth, REG_PPE_TB_HASH_CFG(i),
PATCH_EOF
if grep -q 'PPE_BIND_AGE1_DELTA_TCP_FIN, 30' "$PFILE"; then
  echo "    ✅ 已写入 $PFILE"
else
  echo "    ❌ 补丁写入异常: $PFILE"; exit 1
fi

# 硬件加速链路必需的 conntrack bridge 支持（an7581 target.mk 已默认带，这里做兜底断言）
echo "==== [diy-part2] 检查 kmod-nf-conntrack-bridge 是否在默认包 ===="
if grep -q 'kmod-nf-conntrack-bridge' target/linux/airoha/an7581/target.mk; then
  echo "    ✅ target.mk DEFAULT_PACKAGES 已含 kmod-nf-conntrack-bridge"
else
  echo "    ⚠️  target.mk 未含 kmod-nf-conntrack-bridge，由 .config 显式选中"
fi

########################################
# 3) luci-app-airoha-npu (luanmuc)
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

########################################
# 5) 关键包存在性检查 (feeds 已 update)
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
chk package/luci-app-airoha-npu
if [ "$fail" = "1" ]; then echo "❌ 有包缺失，终止"; exit 1; fi
echo "    ✅ 全部就位"

########################################
# 6) 删掉 LuCI「系统 → 插件」页
#
# 这个页面来自 luci-mod-system 的 luci-plugins 框架：
#   htdocs/luci-static/resources/view/system/plugins.js  (视图)
#   root/usr/share/luci/menu.d/luci-mod-system.json      (菜单项 admin/system/plugins)
# 它只会扫描 /www/luci-static/resources/view/plugins/*.js 里的插件定义，
# 本仓库不使用这套框架，那个目录一个插件都没有 —— 点进去只有一张空表加一个
# 「全局设置」开关，纯属误点，所以整页删掉：
#   1) 删视图文件，页面直接不存在
#   2) 删菜单项，侧边栏不再出现「插件」
# 改 JSON 优先用 python3（buildroot 自身依赖 python3，一定有），
# 没有 python3 时退回 sed 按行删。
########################################
echo "==== [diy-part2] 删除 系统→插件 页面 ===="
PLG_JS=$(find feeds/luci -type f -path '*resources/view/system/plugins.js' 2>/dev/null | head -1)
MENU_JS=$(find feeds/luci -type f -path '*menu.d/luci-mod-system.json' 2>/dev/null | head -1)
if [ -n "$PLG_JS" ]; then
  rm -f "$PLG_JS"
  echo "    ✅ 已删除视图 $PLG_JS"
else
  echo "    ⚠️  未找到 plugins.js（luci 源结构变了？）"
fi
if [ -n "$MENU_JS" ]; then
  cp "$MENU_JS" "$MENU_JS.orig"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$MENU_JS" <<'PY'
import json, sys
p = sys.argv[1]
with open(p, encoding='utf-8') as f:
    d = json.load(f)
d.pop('admin/system/plugins', None)
with open(p, 'w', encoding='utf-8') as f:
    json.dump(d, f, indent='\t', ensure_ascii=False)
    f.write('\n')
PY
  else
    TAB=$'\t'
    sed -i "/\"admin\/system\/plugins\": {/,/^${TAB}},$/d" "$MENU_JS"
  fi
  if grep -q '"admin/system/plugins"' "$MENU_JS"; then
    cp "$MENU_JS.orig" "$MENU_JS"
    echo "    ❌ 菜单项删除失败，已回滚: $MENU_JS"; exit 1
  fi
  rm -f "$MENU_JS.orig"
  echo "    ✅ 已移除菜单项 admin/system/plugins（$MENU_JS）"
else
  echo "    ⚠️  未找到 luci-mod-system.json"
fi

echo "==== [diy-part2] 完成 ===="
