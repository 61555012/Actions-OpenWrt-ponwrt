# Actions-OpenWrt-PonWrt (Nokia XG-040G-MD)

用 GitHub Actions 云编译 **PonWrt**（[pbs05/ponwrt](https://github.com/pbs05/ponwrt)）固件，目标机型 **Nokia XG-040G-MD (UBI)**（`airoha/an7581`，内核 6.18）。

## 目录

```
.github/workflows/openwrt-builder.yml   # 工作流（唯一的编译入口）
.config                                 # 叠加层：只写官方基线之外要加的包/开关
diy-part1.sh                            # feeds update 之前：替换/追加 feed
diy-part2.sh                            # feeds update 之前后：内核统计开关、OAF、mosdns、NPU 面板、去 dummy
diy-part3.sh                            # feeds install 之后：argon v3.1.1 覆盖 feeds 旧版
files/                                  # 原样合并进固件根目录
  etc/config/{network,pon,firewall,upnpd}   # 实机配置（PPPoE、光猫注册、UPnP、加速开关）
  etc/shadow                                # root 密码
  etc/fwxd/feature.bin                      # OAF 特性库
  www/luci-static/resources/oaf/app_icons/  # OAF 应用图标（562 个）
  etc/uci-defaults/99-040g-md               # 首启：加速开关 / 去 dummy / 主题默认值
```

## 编译出来的东西

| 项目 | 说明 |
|---|---|
| 目标 | `airoha/an7581` → `nokia_xg-040g-md-ubi`，产物 `sysupgrade.itb` |
| 硬件加速 | fw4 生成 `inet` + `bridge` 两张 flowtable，L3 与 **L2 桥接**都下到 Airoha PPE；默认 `flow_offloading=1` |
| 每流统计 | `CONFIG_NET_AIROHA_FLOW_STATS=y`（即 `airoha_ppe_foe_flow_stats_*` / `FLOW_CLS_STATS`），编译后会复查生成的内核 `.config` |
| PON | `kmod-airoha-xpon` + `kmod-airoha-pon-frontend` + `kmod-airoha-en7572`（EN7572 光前端）+ `airoha-pond` / `airoha-ponctl` |
| 2.5G 网口 | `kmod-phy-airoha-en8811h`（lan1，`2500base-x` 链路） |
| OAF | `kmod-oaf` + `appfilter` + `luci-app-oaf`（[destan19/OpenAppFilter](https://github.com/destan19/OpenAppFilter) master，当前 7.0.2） |
| UPnP | `miniupnpd-nftables` + `luci-app-upnp`（fw4 是 nftables，必须 nftables 变体） |
| mosdns | `mosdns` 5.3.x（feeds，v5）+ `luci-app-mosdns` / `geo2txt`（[sbwml](https://github.com/sbwml/luci-app-mosdns)）+ `v2ray-geoip` / `v2ray-geosite` |
| 其他插件 | `luci-app-onu` + `luci-app-pon-status`（[naoki66/OpenWrt_ONU_CONFIG](https://github.com/naoki66/OpenWrt_ONU_CONFIG)）、`luci-app-airoha-npu`（[luanmuc](https://github.com/luanmuc/luci-app-airoha-npu)）、`argon v3.1.1` |
| 去除项 | dummy 接口（`kmod-dummy` 不选 + 构建期删 base-files 模板 + 首启 uci 清理） |

## 关键设计说明

### 1. 配置策略：官方基线 + 叠加层

`.config` **不是**完整配置。构建时先做：

```sh
./scripts/kconfig.pl + configs/an7581.config configs/release.config > .config   # 官方基线
sed -i '/^CONFIG_TARGET_DEVICE_airoha_an7581_DEVICE_/d' .config                # 只留本机
echo 'CONFIG_TARGET_DEVICE_airoha_an7581_DEVICE_nokia_xg-040g-md-ubi=y' >> .config
cat 仓库/.config >> .config                                                    # 叠加层
make defconfig
```

官方 `configs/an7581.config`（8906 行）里带着 UBIFS 大小、squashfs 块大小、initramfs、内核参数等**镜像级设置**，手写种子缺了这些很容易编出起不来的镜像，所以直接拿它当底，只把别的机型删掉。设备名里的横杠在 CONFIG 符号里是**保留**的。

### 2. PON 用户态换源（必须替换，不能追加）

`naoki66/OpenWrt_ONU_CONFIG` 是 `pbs05/openwrt-pon-userspace` 的深度 fork，包名（`airoha-pond`、`airoha-ponctl`）与上游**完全重叠**，同时把 `luci-app-pon` 升级为顶级 `luci-app-onu` 并吸收了 `luci-app-iptv`。所以 `diy-part1.sh` 直接把 `feeds.conf.default` 里的 `pon_userspace` 源**替换**掉；追加会导致 `feeds install` 同名包冲突。`pon_drivers`（xPON MAC + 光前端）保持上游官方源。

### 3. 每流统计为什么不在 `.config` 里

`CONFIG_NET_AIROHA_FLOW_STATS` 是**内核 Kconfig** 符号（`depends on NET_AIROHA && NET_AIROHA_NPU`，两者在 `config-6.18` 里都是 `=y`），不是 OpenWrt 包符号。所以只能改 `target/linux/airoha/an7581/config-6.18`（原文件是 `# ... is not set`），由 `diy-part2.sh` 完成，并在编译后再核对一次 `build_dir/.../linux-*/.config`。

### 4. 硬件加速与统计的取舍（重要）

PPE 卸载后 netfilter 看不到被卸载的流量，**OAF 的设备/应用流量统计会失真**（此前实测全量卸载时只剩 ~0.8%）。本固件按你的要求默认 `flow_offloading=1`（`files/etc/config/firewall`），想换精准统计：

```sh
uci set firewall.@defaults[0].flow_offloading='0'
uci set firewall.@defaults[0].flow_offloading_hw='0'
uci commit firewall && /etc/init.d/firewall reload
```

### 5. OAF 从哪来

PonWrt 的 feeds 里**没有** OAF（`feeds.conf.default` 只有 packages/luci/routing/telephony/video/pon_drivers/pon_userspace），`configs/an7581.config` 里那三行 `CONFIG_PACKAGE_kmod-oaf/appfilter/luci-app-appfilter` 是历史残留、选中也不会生效。所以 `diy-part2.sh` 直接拉 [destan19/OpenAppFilter](https://github.com/destan19/OpenAppFilter) 的 master，把 `oaf/`、`open-app-filter/`、`luci-app-oaf/` 三个目录放进 `package/`。kmod 是内核模块，跟着本树 6.18 一起编，vermagic 自动对得上，不会出现外挂 ipk 那种内核 panic。

### 6. argon 为什么要单独一个 diy-part3

feeds（immortalwrt/luci）里自带同名 `luci-theme-argon`。如果在 `feeds install` **之前**删掉 feeds 目录，install 会留下悬空链接/报错；所以放到 install **之后**：删 `package/feeds/luci/luci-theme-argon` 软链 → 删 `feeds/.../luci-theme-argon` 目录 → 克隆 v3.1.1 到 `package/luci-theme-argon`，并断言版本号是 3.x。

### 7. dummy 接口

`kmod-dummy` 不选中；`diy-part2.sh` 会把 base-files 里 `option name 'dummy0'` 的 device 段整段删掉；首启 uci-defaults 再兜底清理 `network` 里所有 dummy 段，已刷过旧固件升级上来的同样会清干净。

### 8. 工具链缓存

两级缓存，键里带 `tools/` `toolchain/` 下所有 `Makefile`/`*.mk` 的哈希：

1. `actions/cache`（正常路径，秒级恢复）
2. GitHub Release `toolchain-cache` 里的 `toolchain-airoha-an7581-<hash>.tzst`（缓存被 LRU 挤掉时的兜底）

缓存命中会自动跳过 `make tools/install` / `toolchain/install`，并用 `sed` 去掉主 `Makefile` 里的 toolchain 依赖。首次约 3~5 小时（含 rust 交叉编译 `airoha-pond`、Go 编译 `mosdns`），之后约 40~70 分钟。

## 使用方法

1. 改完代码直接推到 `main`，或 **Actions → PonWrt-040G-MD → Run workflow**。
2. 仓库 **Settings → Actions → General → Workflow permissions** 需为 **Read and write**（Release 上传与缓存备份要用）。
3. 完成后到 **Releases** 下载 `040g-md-*.itb`。
4. 需要进构建机调试，Run workflow 时把 `ssh` 填 `true`（action-tmate）。

> 编译依赖用 ponwrt README 那份官方列表（比 P3TERX 模板多 `clang` / `lld` / `llvm` / `libyaml-dev` / `python3-ply` / `python3-docutils` / `re2c` / `lib32gcc-s1`）。

## 刷机提醒

- 目标是 **UBI** 变体，产物为 `sysupgrade.itb`；从原厂固件过来请先按 ponwrt 文档确认分区/U-Boot，别在分区布局不明时直接 `sysupgrade`。
- 首启后 `flow_offloading` 已打开，`nft list table bridge fw4` 能看到 `flowtable fb`、`/sys/kernel/debug/ppe/bind` 出现 `BND` 条目即为卸载成功。
- `files/etc/shadow` 与 `files/etc/config/network` 里有 **root 密码哈希和 PPPoE 账号密码**。仓库若是公开的，这些会一起公开，建议改成私有仓库，或把这两处换成占位符。
