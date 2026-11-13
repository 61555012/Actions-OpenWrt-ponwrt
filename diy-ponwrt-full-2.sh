#!/bin/bash
# diy-ponwrt-full-2.sh —— feeds update 之后、feeds install 之前执行
#
# 时机要求：
#   - 必须在 feeds update -a 之后，否则 packages feed 会把目录重新拉回覆盖
#   - 必须在 feeds install -a 之前，否则会留下指向旧目录的软链
#
# 做的事：
#   0) 拉官方 OpenAppFilter：oaf.ko + appfilter + luci-app-oaf 全部编入
#   1) 打开内核每流统计 CONFIG_NET_AIROHA_FLOW_STATS
#   2) PPE 条目 TCP FIN 老化 1s -> 30s
#   3) 补 kmod-nf-conntrack-bridge 检查
#   4) 拉 luci-app-airoha-npu
#   5) 去掉 dummy 接口
#   6) 检查关键包 + 删除「系统 → 插件」页
#
set -e

cd "$(dirname "$0")"
if [ -f feeds.conf.default ] && [ -d scripts ]; then
  echo "已处于源码树根: $(pwd)"
elif [ -f openwrt/feeds.conf.default ]; then
  cd openwrt
  echo "进入源码树: $(pwd)"
else
  echo "❌ 找不到 openwrt 源码树 (feeds.conf.default)"; exit 1
fi

# 0) OAF：后端保留（oaf.ko + appfilter/oafd），官方 Lua 界面不编入
#    界面换成 files/ 里的 oaf_status（用户列表 + 终端详情），所以
#    luci-app-oaf 目录直接删掉——留着也不会被选中，但删干净更好排错。
#    清掉旧的同名目录，避免与 feeds 里的软链冲突
echo "==== [diy-part2] OAF: 拉最新官方源码（保留 oaf.ko + open-app-filter，去掉 luci-app-oaf）===="
find . -type d \( -name "OpenAppFilter" -o -name "luci-app-oaf" -o -name "open-app-filter" \) \
	-exec rm -rf {} + 2>/dev/null || true
rm -rf package/feeds/*/luci-app-oaf package/feeds/*/OpenAppFilter
git clone --depth 1 https://github.com/destan19/OpenAppFilter package/OpenAppFilter
OAFC=$(git -C package/OpenAppFilter rev-parse --short HEAD 2>/dev/null || echo '?')
echo "    官方 OAF commit: ${OAFC}"
rm -rf package/OpenAppFilter/luci-app-oaf
OAF_MISS=0
for d in oaf open-app-filter; do
  if [ -f "package/OpenAppFilter/$d/Makefile" ]; then
    echo "    ✅ package/OpenAppFilter/$d"
  else
    echo "    ❌ 缺少 package/OpenAppFilter/$d"; OAF_MISS=1
  fi
done
if [ "$OAF_MISS" = "1" ]; then
  echo "    ❌ OpenAppFilter 克隆不完整（网络问题？检查 github 连通性）"; exit 1
fi

# 1) 内核每流流量统计
echo "==== [diy-part2] 打开 CONFIG_NET_AIROHA_FLOW_STATS ===="
KC=target/linux/airoha/an7581/config-6.18
if [ -f "$KC" ]; then
  sed -i 's/^# CONFIG_NET_AIROHA_FLOW_STATS is not set$/CONFIG_NET_AIROHA_FLOW_STATS=y/' "$KC"
  # 上游若改名/移动了这一行，直接追加
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

# 2) PPE 条目在 TCP FIN 后的老化 1s -> 30s
#    报文卸载到 PPE 后不再过 netfilter，字节数只能靠 FLOW_CLS_STATS 轮询回写；
#    条目若在 FIN 后 1 秒就被硬件回收，下一次轮询已取不到计数，尾部字节永久丢失。
#    验证：devmem 0x1FB50E40 32 → 0x001E003C（0x1E=30s FIN，0x3C=60s TCP）
#    该值只在 airoha_ppe_hw_init() 锁存一次，运行中 devmem 写回无效。
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

echo "==== [diy-part2] 检查 kmod-nf-conntrack-bridge 是否在默认包 ===="
if grep -q 'kmod-nf-conntrack-bridge' target/linux/airoha/an7581/target.mk; then
  echo "    ✅ target.mk DEFAULT_PACKAGES 已含 kmod-nf-conntrack-bridge"
else
  echo "    ⚠️  target.mk 未含 kmod-nf-conntrack-bridge，由 .config 显式选中"
fi

# 3) luci-app-airoha-npu
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
else
  echo "    ❌ 克隆失败"; exit 1
fi

# 4) 去掉 dummy 接口：从 network 模板里删掉 dummy0 段，避免首启被 netifd 创建
echo "==== [diy-part2] 去除 dummy 接口 ===="
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

# 5) 关键包存在性检查
echo "==== [diy-part2] 关键包存在性检查 ===="
fail=0
chk() { if [ -d "$1" ]; then echo "    ✅ $1"; else echo "    ❌ 缺少 $1"; fail=1; fi; }
chk feeds/pon_drivers/airoha-xpon
chk feeds/pon_drivers/airoha-pon-frontends
# 上游 pbs05 的包名，不是 naoki66 fork 的 luci-app-onu / luci-app-pon-status
chk feeds/pon_userspace/airoha-pon-daemons
chk feeds/pon_userspace/airoha-ponctl
chk feeds/pon_userspace/luci-app-pon
# 上游带 luci-app-iptv，本固件不选中
if [ -d feeds/pon_userspace/luci-app-iptv ]; then
  echo "    ℹ️  feeds/pon_userspace/luci-app-iptv 存在，但不编入固件"
fi
chk package/luci-app-airoha-npu
if [ "$fail" = "1" ]; then echo "❌ 有包缺失，终止"; exit 1; fi
echo "    ✅ 全部就位"

# 6) 删除「系统 → 插件」页（luci-plugins 框架，本仓库不用，点进去是空表）
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
