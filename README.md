# Actions-OpenWrt-PonWrt (Nokia XG-040G-MD)

用 GitHub Actions 云编译 **Nokia XG-040G-MD (UBI)**（`airoha/an7581`，内核 6.18）固件。仓库里并存两条流水线，源码树都是 [pbs05/ponwrt](https://github.com/pbs05/ponwrt)：

| 流水线 | 定位 |
|---|---|
| 标准版 | 光口 + 加速 + OAF / UPnP / mosdns / argon |
| 纯净版 | 只有光口 + 硬件加速转发 |

## 目录

```
# ========== 标准版（PonWrt）==========
.github/workflows/build-040g-ponwrt-full.yml   # 工作流
.config-ponwrt-full                            # 叠加层：只写官方基线之外要加的包/开关
diy-ponwrt-full-1.sh                           # feeds update 之前：替换/追加 feed
diy-ponwrt-full-2.sh                           # feeds update 之后：内核统计开关、Go、OAF、mosdns、NPU 面板、去 dummy
diy-ponwrt-full-3.sh                           # feeds install 之后：argon v3.1.1 覆盖 feeds 旧版
files/                                         # 原样合并进固件根目录
  etc/config/{network,pon,firewall,upnpd,mosdns,onu-internet}   # 实机配置（PPPoE、光猫注册、UPnP、mosdns、加速开关）
  etc/shadow                                # root 密码
  etc/fwxd/feature.bin                      # OAF 特性库
  etc/internet.nft / etc/iptv.nft           # wanup / IPTV 桥接的空规则（firewall include 引用）
  etc/apk/config                            # apk 信任配置：allow-untrusted
  www/luci-static/resources/oaf/app_icons/  # OAF 应用图标（562 个）
  www/luci-static/resources/oui/            # OUI 品牌库（vendors json + 44 个厂牌 svg，设备图标用）
  usr/lib/lua/luci/view/oaf/                # 改过的 OAF 页面（dashboard / user_status / user_detail）
  usr/lib/lua/luci/controller/oaf_*.lua     # 改过的控制器（oaf_user / oaf_dashboard）
  usr/lib/lua/luci/oaf_traffic.lua          # 流量聚合层
  usr/sbin/oaf-flowd + etc/init.d/oaf-flowd # 流量采集器（aarch64 静态二进制 + procd 服务）
  etc/uci-defaults/99-040g-md               # 首启：加速开关 / 去 dummy / 主题默认值

# ========== 纯净版（PonWrt 源码）==========
.github/workflows/build-040g-ponwrt-lite.yml   # 工作流
.config-ponwrt-lite                            # 叠加层：只有 PON / 2.5G / 加速，其余显式关闭
diy-ponwrt-lite-1.sh                           # feeds update 之前：只改 pon_userspace 源
diy-ponwrt-lite-2.sh                           # feeds update 之后：内核统计 + 去 dummy + 出厂默认值 + root 密码 + 关 apk 签名
```

> 纯净版**不引用仓库 `files/`**，不带任何实机配置（没有 PPPoE 账号、没有原密码哈希），默认 root 密码由脚本在构建期设为 `admin123`。

## 编译出来的东西

| 项目 | 说明 |
|---|---|
| 目标 | `airoha/an7581` → `nokia_xg-040g-md-ubi`，产物 `sysupgrade.itb` |
| 硬件加速 | fw4 生成 `inet` + `bridge` 两张 flowtable，L3 与 **L2 桥接**都下到 Airoha PPE；默认 `flow_offloading=1` |
| 每流统计 | `CONFIG_NET_AIROHA_FLOW_STATS=y`（即 `airoha_ppe_foe_flow_stats_*` / `FLOW_CLS_STATS`），编译后会复查生成的内核 `.config-ponwrt-full` |
| PON / 光模块 | `kmod-airoha-xpon` + `kmod-airoha-pon-frontend` + `kmod-airoha-en7572`（EN7572 光前端）+ `airoha-pond` / `airoha-ponctl`，**全部强制 `=y`** |
| 2.5G 网口 | `kmod-phy-airoha-en8811h` + `airoha-en8811h-firmware`，**强制 `=y`**（lan1，`2500base-x` 链路） |
| OAF | 先删除源码/feeds 里自带的 OpenAppFilter，再重新 clone [destan19/OpenAppFilter](https://github.com/destan19/OpenAppFilter) master（当前 7.0.2） |
| UPnP | `miniupnpd-nftables` + `luci-app-upnp`（fw4 是 nftables，必须 nftables 变体） |
| mosdns | [sbwml/luci-app-mosdns](https://github.com/sbwml/luci-app-mosdns) `v5` 整仓（本体 5.3.4 + LuCI + `geo2txt`）+ [sbwml/v2ray-geodata](https://github.com/sbwml/v2ray-geodata) |
| Go 工具链 | 换成 [sbwml/packages_lang_golang](https://github.com/sbwml/packages_lang_golang) `27.x`（Go 1.27.3），失败按 26.x→25.x 回退 |
| 其他插件 | `luci-app-onu` + `luci-app-pon-status`（[naoki66/OpenWrt_ONU_CONFIG](https://github.com/naoki66/OpenWrt_ONU_CONFIG)）、`luci-app-airoha-npu`（[luanmuc](https://github.com/luanmuc/luci-app-airoha-npu)）、`argon v3.1.1` |
| 去除项 | dummy 接口（`kmod-dummy` 不选 + 构建期删 base-files 模板 + 首启 uci 清理） |

## 关键设计说明

### 1. 配置策略：官方基线 + 叠加层

`.config-ponwrt-full` **不是**完整配置。构建时先做：

```sh
./scripts/kconfig.pl + configs/an7581.config configs/release.config > .config   # 官方基线
sed -i '/^CONFIG_TARGET_DEVICE_airoha_an7581_DEVICE_/d' .config                # 只留本机
echo 'CONFIG_TARGET_DEVICE_airoha_an7581_DEVICE_nokia_xg-040g-md-ubi=y' >> .config
cat 仓库/.config >> .config                                                    # 叠加层
make defconfig
```

官方 `configs/an7581.config`（8906 行）里带着 UBIFS 大小、squashfs 块大小、initramfs、内核参数等**镜像级设置**，手写种子缺了这些很容易编出起不来的镜像，所以直接拿它当底，只把别的机型删掉。设备名里的横杠在 CONFIG 符号里是**保留**的。

### 2. PON 用户态换源（必须替换，不能追加）

`naoki66/OpenWrt_ONU_CONFIG` 是 `pbs05/openwrt-pon-userspace` 的深度 fork，包名（`airoha-pond`、`airoha-ponctl`）与上游**完全重叠**，同时把 `luci-app-pon` 升级为顶级 `luci-app-onu` 并吸收了 `luci-app-iptv`。所以 `diy-ponwrt-full-1.sh` 直接把 `feeds.conf.default` 里的 `pon_userspace` 源**替换**掉；追加会导致 `feeds install` 同名包冲突。`pon_drivers`（xPON MAC + 光前端）保持上游官方源。

### 3. 每流统计为什么不在 `.config-ponwrt-full` 里

`CONFIG_NET_AIROHA_FLOW_STATS` 是**内核 Kconfig** 符号（`depends on NET_AIROHA && NET_AIROHA_NPU`，两者在 `config-6.18` 里都是 `=y`），不是 OpenWrt 包符号。所以只能改 `target/linux/airoha/an7581/config-6.18`（原文件是 `# ... is not set`），由 `diy-ponwrt-full-2.sh` 完成，并在编译后再核对一次 `build_dir/.../linux-*/.config`。

### 4. 硬件加速与统计的取舍（重要）

PPE 卸载后 netfilter 看不到被卸载的流量，**OAF 的设备/应用流量统计会失真**（此前实测全量卸载时只剩 ~0.8%）。本固件按你的要求默认 `flow_offloading=1`（`files/etc/config/firewall`），想换精准统计：

```sh
uci set firewall.@defaults[0].flow_offloading='0'
uci set firewall.@defaults[0].flow_offloading_hw='0'
uci commit firewall && /etc/init.d/firewall reload
```

### 4.1 PPE 条目在 TCP FIN 后的老化时间（1s → 30s）

`airoha_ppe_hw_init()` 里 `PPE_BIND_AGE1` 的 `delta_tcp_fin` 上游取 **1 秒**（`delta_tcp` 是 60 秒）。
收到 FIN 的流由硬件按它老化，也就是最后一个包之后约 1 秒条目就从 PPE 表里消失。

这和流量统计**是同一件事**，不是两件事：

- 报文下到 PPE 后不再经过 netfilter，conntrack 里的字节数只能靠驱动定期回写：
  `nf_flow_table` → `FLOW_CLS_STATS` → `airoha_ppe_flow_offload_stats()` → `airoha_ppe_foe_entry_get_stats()`
  → 读 `npu->stats[index]` 的增量累加进 flow 的 `pkts/bytes`。
- `FLOW_CLS_DESTROY`（`airoha_ppe_flow_offload_destroy()`）**只删条目，不取最后一次计数**。
- 所以条目一旦先被硬件回收，下一次 stats 轮询轮到它时 `airoha_ppe_foe_get_flow_stats_index()` 已经查不到 hash，
  尾部这一截字节永久丢失——**秒级结束的大流量丢得最狠**，实测同一批 3×9.7MB 下载，精度在 14%~145% 之间抖。
- 采集器 `/usr/sbin/oaf-flowd` 读的正是 conntrack 计数器（netlink destroy 事件 + `/proc/net/nf_conntrack`），
  丢的就是页面上每设备 / 每应用的流量数字。

两个 diy 脚本（`diy-ponwrt-full-2.sh` / `diy-ponwrt-lite-2.sh`）会往
`target/linux/airoha/patches-6.18/700-net-airoha-ppe-raise-tcp-fin-age.patch` 写一个补丁，
把 `delta_tcp_fin` 改成 **30 秒**；编译后的 `Verify built kernel config` 步骤会复查内核源码里的实际值，
没生效直接判失败，不会静默产出“没改过”的固件。

- **效果**：条目能活到下一次 stats 轮询之后再回收，同一批下载的统计精度收敛到 ~104%（≈ 以太网/IP/TCP 头开销）。
- **代价**：已结束的连接多占 30 秒槽位（表 16K 槽，家用几百条流，无压力），TCP 常态老化 60s 不变。
- **验证**：刷完 `devmem 0x1FB50E40 32` 读到的就是初始化时锁存的实际值——
  `0x001E003C` = FIN 30s / TCP 60s（补丁生效），`0x0001003C` = 还是源码默认 1 秒。
  运行中把寄存器写回去**无效**（实测写入后条目仍在 0.5s 内回收），只能改源码重编。
- **撤销**：把补丁里的 `30` 改回 `1`，或整段 heredoc 删掉。

### 4.2 删掉 LuCI 的「系统 → 插件」页

这一页来自 `luci-mod-system` 的 luci-plugins 框架：视图 `view/system/plugins.js` + 菜单项 `admin/system/plugins`。
它只扫描 `/www/luci-static/resources/view/plugins/*.js` 里的插件定义，本固件那个目录是**空的**（没有任何插件注册），
点进去只有一张空表和一个「全局设置」开关。两个 diy-ponwrt-*-2.sh 在 `feeds update` 之后、`feeds install` 之前
把视图文件删掉、把菜单项从 `luci-mod-system.json` 里摘掉（python3 改 JSON，无 python3 时退回 sed），
所以编出来的固件里没这一页，不是靠首启脚本事后删。

### 4.3 关掉 apk 的安装签名要求

apk（apk-tools 3）只装签名能被 `/etc/apk/keys/` 里公钥验证的包，装自编译 / 第三方 .apk 会直接报
`UNTRUSTED signature`。全局开关只有一条：配置文件 `/etc/apk/config` 里的 `allow-untrusted`
（**它是无参数开关**，写成 `allow-untrusted=yes` 只会得到一条 warning 并被忽略）。

- 标准版：`files/etc/apk/config` 随覆盖层进固件。
- 纯净版：`diy-ponwrt-lite-2.sh` 写进 `package/base-files/files/etc/apk/config`（纯净版不引用 `files/`）。

验证（干净环境下）：

```sh
apk add /tmp/x.apk              # ERROR: /tmp/x.apk: UNTRUSTED signature
printf 'allow-untrusted\n' > /etc/apk/config
apk add /tmp/x.apk              # 签名这道关卡不再拦
```

### 4.4 files/ 里定制的 OAF 页面与采集器

上游 OAF 包（`appfilter` + `luci-app-oaf`）原样编进固件，仓库用 `files/` 覆盖层把自己的改动叠上去
（`files/` 在包安装之后展开到根文件系统，同路径即生效）：

| 路径 | 改了什么 |
|---|---|
| `usr/lib/lua/luci/view/oaf/dashboard.htm` | 仪表盘：卡片重排、移动端适配、图表 resize、分页不重绘/不滚顶 |
| `usr/lib/lua/luci/view/oaf/user_status.htm` | 用户列表：OUI 品牌头像（`/luci-static/resources/oui/`）、v4/v6 双行流量、卡片结构指纹防闪烁 |
| `usr/lib/lua/luci/view/oaf/user_detail.htm` | 设备详情：移动端适配、24 列小时柱、页签内横向滚动 |
| `usr/lib/lua/luci/controller/oaf_user.lua` | 全量排序后再分页（跨页全局降序）、小时统计、上下线记录 |
| `usr/lib/lua/luci/controller/oaf_dashboard.lua` | 首页聚合、按类型统计、`device_apps` / 三路合并的「正在访问」 |
| `usr/lib/lua/luci/oaf_traffic.lua` | 流量聚合层（读 `/tmp/oaf-flow/*.json`，按天/月/设备/应用切片） |
| `usr/sbin/oaf-flowd` | 采集器（aarch64 静态二进制）：netlink 订阅 conntrack destroy + `/proc/net/nf_conntrack` 全表扫描，按设备/小时/应用聚合，写 `/tmp/oaf-flow/{stats,hourly,day,mon}.json`，持久化到 `/etc/oaf/data/{day,mon}` |
| `etc/init.d/oaf-flowd` | procd 服务（START=95，respawn） |
| `www/luci-static/resources/oui/` | OUI 品牌库：`vendors-<hash>.json`（42 家 / 8712 个前缀）+ 44 个厂牌 svg |

> 采集器的 Go 源码在开发机上（`oaf-flowd_src/`），这里入库的是编好的 aarch64 二进制；
> 换内核/换架构后要重新 `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build` 再覆盖。

### 5. OAF 为什么要“先删再拉”

PonWrt 主树本身不含 OAF（`feeds.conf.default` 只有 packages/luci/routing/telephony/video/pon_drivers/pon_userspace），`configs/an7581.config` 里那三行 `CONFIG_PACKAGE_kmod-oaf/appfilter/luci-app-appfilter` 是历史残留。但 feeds 或旧分支可能带一份旧版 OpenAppFilter，**用户态 `appfilter` 与 `kmod-oaf` 版本不匹配会直接 insmod 失败**。所以 `diy-ponwrt-full-2.sh` 按 S20P 的做法：

```sh
# 先删
find package feeds -maxdepth 5 \( -name OpenAppFilter -o -name open-app-filter -o -name luci-app-oaf -o -name oaf \) -exec rm -rf {} +
rm -rf package/feeds/*/luci-app-oaf
# 再拉最新
git clone --depth 1 https://github.com/destan19/OpenAppFilter.git /tmp/oafsrc
cp -a /tmp/oafsrc/{oaf,open-app-filter,luci-app-oaf} package/
```

kmod 是内核模块，跟着本树 6.18 一起编，vermagic 自动对得上，不会出现外挂 ipk 那种内核 panic。

### 5.1 mosdns 为什么要换 Go

`mosdns` 5.3.x 需要较新的 Go，而 immortalwrt/packages 里的 `lang/golang` 版本偏旧。`diy-ponwrt-full-2.sh` 在 `feeds update` 之后把 `feeds/packages/lang/golang` 整个换成 [sbwml/packages_lang_golang](https://github.com/sbwml/packages_lang_golang)：默认 `27.x`（Go 1.27.3），拉取失败自动回退 `26.x` → `25.x`。同时删掉源码树自带的 `net/mosdns`、`net/v2ray-geodata`（包名与 sbwml 版本重名会导致 duplicate package），改用 `sbwml/luci-app-mosdns v5` 整仓 + `sbwml/v2ray-geodata`；`diy-ponwrt-full-3.sh` 会再清一遍 `package/feeds` 下的悬空链接和同名残留。

### 5.2 mosdns 的 adlist 空文件：一条配置把 DNS 和时间一起搞死

`mosdns` 的配置生成器 `get_adlist()`（`/usr/share/mosdns/mosdns.uc`）**只在 `adblock != 1` 时**
才 `writefile('/var/mosdns/disable-ads.txt', '')`；而 `adblock=1` 且 `ad_source` 为空时它返回空串，
init 脚本的 fail-safe 于是把 adlist 指向这个**从未被创建**的文件：

```
failed to init plugin #11 adlist: /var/mosdns/disable-ads.txt: no such file or directory
procd: Instance mosdns::mosdns in a crash loop 6 crashes
```

后果是链式的：`dnsmasq` 配的是 `noresolv=1` + `server=127.0.0.1#5335`，mosdns 起不来就等于
**整个局域网没有 DNS**；而本机没有 RTC（`hwclock: can't open '/dev/rtc0'`），开机时钟取自
`/etc` 最新文件的 mtime（≈刷机时间），NTP 的 peer 又全是域名 —— DNS 一死就永远校不回时间。
实测这台机器就这么停在刷机那天（落后 14 天 12 小时），界面上所有时间、OAF 的「今日」全错。

修法三处，互相兜底：

1. **`files/etc/config/mosdns`**：`adblock '0'`。没有 `ad_source` 时它本来就不拦截任何东西，
   开着只会崩。要开拦截必须**先**加 `ad_source`（`update_adlist` 才会真的落一份列表），
   再把开关改回 `1`。
2. **`files/etc/uci-defaults/99-ponwrt-time`**：首次启动兜底建 `/var/mosdns/disable-ads.txt`，
   保证从旧固件升级上来（`/etc/config` 被保留、仍是 `adblock=1`）的机器也能起来。
3. **同一个脚本**：时区 `CST-8` / `Asia/Shanghai`（出厂是 `GMT0`），NTP 服务器改成纯 IP
   （`203.107.6.88`、`120.25.115.20`、`182.92.12.11`）—— 用域名的话，DNS 挂着的时候等于没配。

> 2026-11 实测：`114.118.7.161/163`（国家授时中心）、`223.5.5.5`、`119.28.183.184` 都不回包；
> busybox `ntpd` 没有 1000 s 的 step 上限，一步跳 14 天也能校正。
> 根治还得等上游把 `get_adlist()` 改成 `adblock=1` 时也建空文件，那时第 2 条就可以删了。

### 6. argon 为什么要单独一个 diy-ponwrt-full-3

feeds（immortalwrt/luci）里自带同名 `luci-theme-argon`。如果在 `feeds install` **之前**删掉 feeds 目录，install 会留下悬空链接/报错；所以放到 install **之后**：删 `package/feeds/luci/luci-theme-argon` 软链 → 删 `feeds/.../luci-theme-argon` 目录 → 克隆 v3.1.1 到 `package/luci-theme-argon`，并断言版本号是 3.x。

### 7. dummy 接口

`kmod-dummy` 不选中；`diy-ponwrt-full-2.sh` 会把 base-files 里 `option name 'dummy0'` 的 device 段整段删掉；首启 uci-defaults 再兜底清理 `network` 里所有 dummy 段，已刷过旧固件升级上来的同样会清干净。

### 8. 工具链缓存

两级缓存，键里带 `tools/` `toolchain/` 下所有 `Makefile`/`*.mk` 的哈希：

1. `actions/cache`（正常路径，秒级恢复）
2. GitHub Release `toolchain-cache` 里的 `toolchain-airoha-an7581-<hash>.tzst`（缓存被 LRU 挤掉时的兜底）

缓存命中会自动跳过 `make tools/install` / `toolchain/install`，并用 `sed` 去掉主 `Makefile` 里的 toolchain 依赖。首次约 3~5 小时（含 rust 交叉编译 `airoha-pond`、Go 编译 `mosdns`），之后约 40~70 分钟。

## 纯净版（Lite）

两条流水线互不干扰，文件名/配置名/tag 前缀都能一眼区分：

| | 标准版 | 纯净版（PonWrt） |
|---|---|---|
| 工作流 | `build-040g-ponwrt-full.yml` | `build-040g-ponwrt-lite.yml` |
| 配置 | `.config-ponwrt-full` | `.config-ponwrt-lite` |
| DIY 脚本 | `diy-ponwrt-full-1/2/3.sh` | `diy-ponwrt-lite-1/2.sh` |
| 落地文件 | `files/` | **无** |
| Release tag | `040g-md-*` | `ponwrt-lite-040g-md-*` |
| 工具链缓存 | `toolchain-airoha-an7581-*` | 同左（共用） |
| 定位 | 光口 + 加速 + OAF/UPnP/mosdns/argon | **只有光口 + 硬件加速转发** |

纯净版保留的东西（都是一台 ONU 上网绕不开的）：

- PON 驱动栈 `kmod-airoha-xpon` / `kmod-airoha-pon-frontend` / `kmod-airoha-en7572` + `airoha-pond` / `airoha-ponctl`，全部 `=y`
- 2.5G PHY `kmod-phy-airoha-en8811h` + 固件，全部 `=y`
- 硬件加速：`kmod-nf-conntrack-bridge` / `kmod-nft-offload` / `kmod-nf-flow` + 内核 `CONFIG_NET_AIROHA_FLOW_STATS=y`，`flow_offloading=1`、`flow_offloading_hw=1`（L2 桥接 + L3 路由都走 PPE）
- `luci-app-onu` / `luci-app-pon-status`（**配注册/桥接要用，算基础功能不是可选插件**）
- 内置 `luci-theme-bootstrap` 主题；不选 `kmod-dummy`

**不带仓库 `files/`**：纯净版不在固件里塞任何实机配置（没有 PPPoE 账号、没有原 root 密码哈希、没有 UPnP/OAF 配置），出厂状态 = 上游默认 + 下面这些由脚本写入的默认值：

| 默认值 | 写入位置 | 说明 |
|---|---|---|
| root 密码 `admin123` | `package/base-files/files/etc/shadow`（构建期用 `openssl passwd -5` 生成哈希） | 可在工作流 env 里改 `ROOT_PASS` |
| `flow_offloading=1` + `flow_offloading_hw=1` | `package/base-files/files/etc/uci-defaults/99-lite-bridge`（构建期生成） | 首启即开 L2/L3 硬件加速，无需进 LuCI 手动勾 |
| `allow-untrusted`（apk 不校验签名） | `package/base-files/files/etc/apk/config`（构建期生成） | 见 4.3 |
| 无 dummy 接口 | 同上去模板 + 首启兜底清理 | — |

也就是说，刷进去之后是干净的上游默认网络（LAN 侧 `192.168.1.1`，`root` / `admin123`），PPPoE 或桥接、PON 注册都在 **网络 → ONU** 里自己配，不用清理别人的残留配置。

纯净版显式关闭（写成 `# CONFIG_... is not set`，防止官方基线或 feeds 默认值把它们带进来）：

`luci-theme-argon`、`luci-app-argon-config`、`kmod-oaf`、`appfilter`、`luci-app-oaf`、`mosdns`、`luci-app-mosdns`、`geo2txt`、`v2ray-geoip/geosite`、`luci-app-upnp`、`miniupnpd-nftables`、`luci-app-airoha-npu`、`htop/nano`。

工作流里有 `absent()` 断言：一旦哪个被依赖重新带进 `.config` 就直接失败，不会悄悄编出一个"不纯净"的固件。纯净版**不换 Go 工具链、不 clone 任何第三方仓库**，所以首次编译比标准版快，产物也更小。

两条 PonWrt 流水线共用同一个 `toolchain-cache` Release 与同一把缓存键，先进先得：标准版编过一次，纯净版就直接复用工具链，反之亦然。为此两边都设了 `concurrency: ponwrt-toolchain-cache` 串行。

> 想把纯净版做到极致：删掉 `diy-ponwrt-lite-1.sh` 里的 feed 替换，并把 `.config-ponwrt-lite` 里的 `luci-app-onu` / `luci-app-pon-status` 关掉，就只剩纯上游 `luci-app-pon` + 驱动，全部靠 UCI 手工配 `/etc/config/pon`。

## 使用方法

1. 改完代码直接推到 `main`，或到 **Actions** 里选手动触发（两个工作流都支持 `workflow_dispatch`，标准版还支持 `repository_dispatch`）：
   - 标准版 → **040G-MD 标准版 (PonWrt)**
   - 纯净版 → **040G-MD 纯净版 (PonWrt)**
2. 仓库 **Settings → Actions → General → Workflow permissions** 需为 **Read and write**（Release 上传与缓存备份要用）。
3. 完成后到 **Releases** 下载：标准版 `040g-md-*.itb`、纯净版 `ponwrt-lite-040g-md-*.itb`。
4. 需要进构建机调试，Run workflow 时把 `ssh` 填 `true`（action-tmate）。

> 编译依赖用 ponwrt README 那份官方列表（比 P3TERX 模板多 `clang` / `lld` / `llvm` / `libyaml-dev` / `python3-ply` / `python3-docutils` / `re2c` / `lib32gcc-s1`）。

## 刷机提醒

- 目标是 **UBI** 变体，产物为 `sysupgrade.itb`；从原厂固件过来请先按 ponwrt 文档确认分区/U-Boot，别在分区布局不明时直接 `sysupgrade`。
- 首启后 `flow_offloading` 已打开，`nft list table bridge fw4` 能看到 `flowtable fb`、`/sys/kernel/debug/ppe/bind` 出现 `BND` 条目即为卸载成功。
- `files/etc/shadow` 与 `files/etc/config/network` 里有 **root 密码哈希和 PPPoE 账号密码**。仓库若是公开的，这些会一起公开，建议改成私有仓库，或把这两处换成占位符。
