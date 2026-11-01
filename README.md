# Actions-OpenWrt-PonWrt / LEDE (Nokia XG-040G-MD)

用 GitHub Actions 云编译 **Nokia XG-040G-MD (UBI)**（`airoha/an7581`，内核 6.18）固件。仓库里并存三条流水线：

| 流水线 | 源码 | 定位 |
|---|---|---|
| 标准版 | [pbs05/ponwrt](https://github.com/pbs05/ponwrt) | 光口 + 加速 + OAF / UPnP / mosdns / argon |
| 纯净版（PonWrt） | [pbs05/ponwrt](https://github.com/pbs05/ponwrt) | 只有光口 + 硬件加速转发 |
| 纯净版（LEDE） | [coolsnowwolf/lede](https://github.com/coolsnowwolf/lede) | 同上，但源码树换成 LEDE |

## 目录

```
# ========== 标准版（PonWrt）==========
.github/workflows/build-040g-ponwrt-full.yml   # 工作流
.config-ponwrt-full                            # 叠加层：只写官方基线之外要加的包/开关
diy-ponwrt-full-1.sh                           # feeds update 之前：替换/追加 feed
diy-ponwrt-full-2.sh                           # feeds update 之后：内核统计开关、Go、OAF、mosdns、NPU 面板、去 dummy
diy-ponwrt-full-3.sh                           # feeds install 之后：argon v3.1.1 覆盖 feeds 旧版
files/                                         # 原样合并进固件根目录
  etc/config/{network,pon,firewall,upnpd}   # 实机配置（PPPoE、光猫注册、UPnP、加速开关）
  etc/shadow                                # root 密码
  etc/fwxd/feature.bin                      # OAF 特性库
  www/luci-static/resources/oaf/app_icons/  # OAF 应用图标（562 个）
  etc/uci-defaults/99-040g-md               # 首启：加速开关 / 去 dummy / 主题默认值

# ========== 纯净版（PonWrt 源码）==========
.github/workflows/build-040g-ponwrt-lite.yml   # 工作流
.config-ponwrt-lite                            # 叠加层：只有 PON / 2.5G / 加速，其余显式关闭
diy-ponwrt-lite-1.sh                           # feeds update 之前：只改 pon_userspace 源
diy-ponwrt-lite-2.sh                           # feeds update 之后：内核统计 + 去 dummy + 出厂默认值 + root 密码

# ========== 纯净版（LEDE 源码）==========
.github/workflows/build-040g-lede-lite.yml     # 工作流
.config-lede-lite                              # 最小种子（目标 + 包），其余交给 defconfig
diy-lede-lite-1.sh                             # feeds update 之前：追加 PON 两个 feed
diy-lede-lite-2.sh                             # feeds update 之后：内核统计 + 去 dummy + 出厂默认值 + root 密码
```

> 两个纯净版都**不引用仓库 `files/`**，不带任何实机配置（没有 PPPoE 账号、没有原密码哈希），默认 root 密码由脚本在构建期设为 `admin123`。

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

三条流水线互不干扰，文件名/配置名/tag 前缀都能一眼区分：

| | 标准版 | 纯净版（PonWrt） | 纯净版（LEDE） |
|---|---|---|---|
| 工作流 | `build-040g-ponwrt-full.yml` | `build-040g-ponwrt-lite.yml` | `build-040g-lede-lite.yml` |
| 配置 | `.config-ponwrt-full` | `.config-ponwrt-lite` | `.config-lede-lite`（最小种子） |
| DIY 脚本 | `diy-ponwrt-full-1/2/3.sh` | `diy-ponwrt-lite-1/2.sh` | `diy-lede-lite-1/2.sh` |
| 落地文件 | `files/` | **无** | **无** |
| Release tag | `040g-md-*` | `ponwrt-lite-040g-md-*` | `lede-lite-040g-md-*` |
| 工具链缓存 | `toolchain-airoha-an7581-*` | 同左（共用） | `toolchain-lede-an7581-*`（独立） |
| 定位 | 光口 + 加速 + OAF/UPnP/mosdns/argon | **只有光口 + 硬件加速转发** | 同左，换 LEDE 源码 |

两个纯净版保留的东西一致（都是一台 ONU 上网绕不开的）：

- PON 驱动栈 `kmod-airoha-xpon` / `kmod-airoha-pon-frontend` / `kmod-airoha-en7572` + `airoha-pond` / `airoha-ponctl`，全部 `=y`
- 2.5G PHY `kmod-phy-airoha-en8811h` + 固件，全部 `=y`
- 硬件加速：`kmod-nf-conntrack-bridge` / `kmod-nft-offload` / `kmod-nf-flow` + 内核 `CONFIG_NET_AIROHA_FLOW_STATS=y`，`flow_offloading=1`、`flow_offloading_hw=1`（L2 桥接 + L3 路由都走 PPE）
- `luci-app-onu` / `luci-app-pon-status`（**配注册/桥接要用，算基础功能不是可选插件**）
- 内置 `luci-theme-bootstrap` 主题；不选 `kmod-dummy`

**不带仓库 `files/`**：纯净版不在固件里塞任何实机配置（没有 PPPoE 账号、没有原 root 密码哈希、没有 UPnP/OAF 配置），出厂状态 = 上游默认 + 下面这些由脚本写入的默认值：

| 默认值 | 写入位置 | 说明 |
|---|---|---|
| root 密码 `admin123` | `package/base-files/files/etc/shadow`（构建期用 `openssl passwd -5` 生成哈希） | 可在工作流 env 里改 `ROOT_PASS` |
| `flow_offloading=1` + `flow_offloading_hw=1` | `package/base-files/files/etc/uci-defaults/99-{lite-bridge,lede-lite-bridge}`（构建期生成） | 首启即开 L2/L3 硬件加速，无需进 LuCI 手动勾 |
| 无 dummy 接口 | 同上去模板 + 首启兜底清理 | — |

也就是说，刷进去之后是干净的上游默认网络（LAN 侧 `192.168.1.1`，`root` / `admin123`），PPPoE 或桥接、PON 注册都在 **网络 → ONU** 里自己配，不用清理别人的残留配置。

纯净版显式关闭（写成 `# CONFIG_... is not set`，防止官方基线或 feeds 默认值把它们带进来）：

`luci-theme-argon`、`luci-app-argon-config`、`kmod-oaf`、`appfilter`、`luci-app-oaf`、`mosdns`、`luci-app-mosdns`、`geo2txt`、`v2ray-geoip/geosite`、`luci-app-upnp`、`miniupnpd-nftables`、`luci-app-airoha-npu`、`htop/nano`。

工作流里有 `absent()` 断言：一旦哪个被依赖重新带进 `.config` 就直接失败，不会悄悄编出一个"不纯净"的固件。纯净版**不换 Go 工具链、不 clone 任何第三方仓库**，所以首次编译比标准版快，产物也更小。

### PonWrt 纯净版 vs LEDE 纯净版

| | PonWrt 纯净版 | LEDE 纯净版 |
|---|---|---|
| 配置来源 | 官方 `configs/an7581.config` + `release.config` 基线，再叠 `.config-ponwrt-lite` | LEDE 无官方 an7581 基线，`.config-lede-lite` 是最小种子 + `make defconfig` 补齐 |
| PON feeds | 替换 `pon_userspace` 源 + 保留下游 `pon_drivers` | 两者都是**追加**（LEDE 原本没有） |
| 设备符号 | `CONFIG_TARGET_DEVICE_airoha_an7581_DEVICE_nokia_xg-040g-md-ubi`（MULTI_PROFILE） | `CONFIG_TARGET_airoha_an7581_DEVICE_nokia_xg-040g-md-ubi`（单 profile，工作流会兜底两种写法） |
| 内核 | 6.18（ponwrt 自带 patch 集） | 6.18（LEDE 自带 patch 集，`# CONFIG_NET_AIROHA_FLOW_STATS is not set` 同样存在） |
| L2 桥接前置 | 选包 `kmod-nf-conntrack-bridge` | LEDE 没有这个包，改为把 `CONFIG_BRIDGE_NETFILTER` / `CONFIG_NF_CONNTRACK_BRIDGE` 直接写成 `=y` 编进内核（`generic/config-6.18` 里默认是 not set） |
| 工具链缓存 | 与标准版共用 `toolchain-airoha-an7581-*` | 独立 `toolchain-lede-an7581-*`（tools/toolchain 与 PonWrt 不同，不能混用） |

两条 PonWrt 流水线共用同一个 `toolchain-cache` Release 与同一把缓存键，先进先得：标准版编过一次，纯净版就直接复用工具链，反之亦然。为此两边都设了 `concurrency: ponwrt-toolchain-cache` 串行；LEDE 用自己的一组 `lede-toolchain-cache`。

> 想把纯净版做到极致：删掉 `diy-ponwrt-lite-1.sh` 里的 feed 替换，并把 `.config-ponwrt-lite` 里的 `luci-app-onu` / `luci-app-pon-status` 关掉，就只剩纯上游 `luci-app-pon` + 驱动，全部靠 UCI 手工配 `/etc/config/pon`。

## 使用方法

1. 改完代码直接推到 `main`，或到 **Actions** 里选手动触发（三个工作流都支持 `workflow_dispatch`，标准版还支持 `repository_dispatch`）：
   - 标准版 → **040G-MD 标准版 (PonWrt)**
   - 纯净版 → **040G-MD 纯净版 (PonWrt)**
   - 纯净版 → **040G-MD 纯净版 (LEDE)**
2. 仓库 **Settings → Actions → General → Workflow permissions** 需为 **Read and write**（Release 上传与缓存备份要用）。
3. 完成后到 **Releases** 下载：标准版 `040g-md-*.itb`、PonWrt 纯净版 `ponwrt-lite-040g-md-*.itb`、LEDE 纯净版 `lede-lite-040g-md-*.itb`。
4. 需要进构建机调试，Run workflow 时把 `ssh` 填 `true`（action-tmate）。

> 编译依赖用 ponwrt README 那份官方列表（比 P3TERX 模板多 `clang` / `lld` / `llvm` / `libyaml-dev` / `python3-ply` / `python3-docutils` / `re2c` / `lib32gcc-s1`）。

## 刷机提醒

- 目标是 **UBI** 变体，产物为 `sysupgrade.itb`；从原厂固件过来请先按 ponwrt 文档确认分区/U-Boot，别在分区布局不明时直接 `sysupgrade`。
- 首启后 `flow_offloading` 已打开，`nft list table bridge fw4` 能看到 `flowtable fb`、`/sys/kernel/debug/ppe/bind` 出现 `BND` 条目即为卸载成功。
- `files/etc/shadow` 与 `files/etc/config/network` 里有 **root 密码哈希和 PPPoE 账号密码**。仓库若是公开的，这些会一起公开，建议改成私有仓库，或把这两处换成占位符。
