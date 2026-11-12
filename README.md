# Actions-OpenWrt-PonWrt (Nokia XG-040G-MD)

用 GitHub Actions 云编译 **Nokia XG-040G-MD (UBI)**（`airoha/an7581`，内核 6.18）固件。
源码树是 [pbs05/ponwrt](https://github.com/pbs05/ponwrt) `master`，仓库只保留一条标准版流水线。

## 目录

```
.github/workflows/build-040g-ponwrt-full.yml   # 唯一的工作流
.github/workflows/update-checker.yml           # 上游更新时触发 repository_dispatch
.config-ponwrt-full                            # 叠加层：官方基线之外要加/要关的包
diy-ponwrt-full-1.sh                           # feeds update 前：钉住 feed 源
diy-ponwrt-full-2.sh                           # feeds update 后：OAF、内核每流统计、PPE FIN 补丁、NPU 面板、去 dummy
diy-ponwrt-full-3.sh                           # feeds install 后：argon v3.1.1 覆盖 feeds 旧版
files/                                         # 原样合并进固件根目录
  etc/config/{network,pon,firewall,upnpd}      # 实机配置（PPPoE、光猫注册、UPnP、加速开关）
  etc/shadow                                   # root 密码
  etc/fwxd/feature.bin                         # OAF 应用特征库
  etc/apk/{config,repositories}                # 关签名校验 + PKU 软件源 6 条
  www/luci-static/resources/oaf/app_icons/     # OAF 界面的 562 个应用图标
```

## 编译出来的东西

| 项目 | 说明 |
|---|---|
| 目标 | `airoha/an7581` → `nokia_xg-040g-md-ubi`，产物 `sysupgrade.itb` |
| 硬件加速 | fw4 生成 `inet` + `bridge` 两张 flowtable，L3 与 L2 桥接都下到 Airoha PPE；默认 `flow_offloading=1` |
| 每流统计 | `CONFIG_NET_AIROHA_FLOW_STATS=y`，编译后复查生成的内核 `.config` |
| PPE FIN 老化 | `delta_tcp_fin` 1s → 30s，保证卸载流的尾部字节能被 conntrack 回写采到 |
| PON / 光模块 | `kmod-airoha-xpon` + `kmod-airoha-pon-frontend` + `kmod-airoha-en7572` + `airoha-pond` / `airoha-ponctl`，全部 `=y` |
| 2.5G 网口 | `kmod-phy-airoha-en8811h` + `airoha-en8811h-firmware`，`=y`（lan1，`2500base-x`） |
| UPnP | `miniupnpd-nftables` + `luci-app-upnp` |
| OAF | 官方 [destan19/OpenAppFilter](https://github.com/destan19/OpenAppFilter) 原样编译：`kmod-oaf` + `appfilter` + `luci-app-oaf` |
| 其他插件 | `luci-app-pon`（上游 pbs05）、`luci-app-airoha-npu`（[luanmuc](https://github.com/luanmuc/luci-app-airoha-npu)）、`argon v3.1.1` |
| 不编入 | `luci-app-iptv`、mosdns 整套、`kmod-dummy`；无线栈 `kmod-mac80211` / `kmod-cfg80211` / `kmod-mt76-core` / `-connac` / `wpad-openssl` / `hostapd-common` / `wifi-scripts` / `wireless-regdb` |
| OMCI 兼容性 | `omcc_version` 出厂默认 `0x86` |

## 关键设计

### 1. 配置策略：官方基线 + 叠加层

`.config-ponwrt-full` 不是完整配置。构建时先做：

```sh
./scripts/kconfig.pl + configs/an7581.config configs/release.config > .config   # 官方基线
sed -i '/^CONFIG_TARGET_DEVICE_airoha_an7581_DEVICE_/d' .config                # 只留本机
echo 'CONFIG_TARGET_DEVICE_airoha_an7581_DEVICE_nokia_xg-040g-md-ubi=y' >> .config
cat 仓库/.config-ponwrt-full >> .config                                       # 叠加层
make defconfig
```

官方 `an7581.config` 带 UBIFS 大小、squashfs 块大小、initramfs、内核参数等镜像级设置，
缺了容易编出起不来的镜像，所以拿它当底，只删掉别的机型。

### 2. PON 用户态用上游 pbs05

`diy-ponwrt-full-1.sh` 把 `feeds.conf.default` 的 `pon_userspace` 钉到
`pbs05/openwrt-pon-userspace`（`luci-app-pon` + `airoha-pon-daemons` + `airoha-ponctl`），
`pon_drivers` 钉到 `pbs05/openwrt-pon-drivers`（xPON MAC + 光前端）。

两个 feed 的包名都与上游重叠，必须改写而不能追加，否则 `feeds install` 同名包冲突。

### 3. 每流统计不在 `.config-ponwrt-full` 里

`CONFIG_NET_AIROHA_FLOW_STATS` 是内核 Kconfig 符号（`depends on NET_AIROHA && NET_AIROHA_NPU`），
不是 OpenWrt 包符号，只能改 `target/linux/airoha/an7581/config-6.18`，
由 `diy-ponwrt-full-2.sh` 完成，编译后再核对 `build_dir/.../linux-*/.config`。

关掉它，`airoha_ppe_foe_entry_get_stats()` 直接返回 0，被 PPE 卸载的流在 conntrack 里字节数不涨。

### 4. 硬件加速与统计的取舍

PPE 卸载后报文不再经过 netfilter，conntrack 的字节数只能靠驱动周期性回写。本固件默认
`flow_offloading=1`；完全关掉可以让软件侧逐包记账，但会损失全部硬件转发性能：

```sh
uci set firewall.@defaults[0].flow_offloading='0'
uci set firewall.@defaults[0].flow_offloading_hw='0'
uci commit firewall && /etc/init.d/firewall reload
```

#### 4.1 PPE 条目 TCP FIN 后老化 1s → 30s

上游 `airoha_ppe_hw_init()` 给 `PPE_BIND_AGE1` 的 `delta_tcp_fin` 取 1 秒（`delta_tcp` 60 秒），
收到 FIN 的流约 1 秒后条目就从 PPE 表消失。而字节数靠 `FLOW_CLS_STATS` 轮询回写，
`FLOW_CLS_DESTROY` 只删条目不取最后一次计数——条目先被回收，尾部字节就永久丢失，
秒级结束的大流量丢得最狠。

`diy-ponwrt-full-2.sh` 往 `target/linux/airoha/patches-6.18/` 写补丁改成 30 秒，
编译后复查内核源码里的实际值，没生效直接判失败。

- 代价：已结束的连接多占 30 秒槽位（表 16K 槽，家用无压力），TCP 常态老化 60s 不变
- 验证：`devmem 0x1FB50E40 32` → `0x001E003C` 为生效，`0x0001003C` 为源码默认

#### 4.2 删掉 LuCI 的「系统 → 插件」页

该页来自 luci-plugins 框架，本固件不用它，点进去只有空表。`diy-ponwrt-full-2.sh`
删视图 `view/system/plugins.js` 并从 `luci-mod-system.json` 摘掉 `admin/system/plugins` 菜单项。

### 5. OMCC 版本 = 0x86

`files/etc/config/pon` 里 `option omcc_version '0x86'`（上游默认 `0xb0`），
兼容不认第三方 ONU 的华为 OLT。工作流编译前校验该值，不是 `0x86` 直接失败。

### 6. argon 为什么单独一个 diy-3

feeds 里自带同名 `luci-theme-argon`（v2 系列）。在 `feeds install` 之前删会留下悬空链接，
所以放到 install 之后：删软链 → 删 feeds 目录 → 克隆 v3.1.1 到 `package/`，并断言版本号 3.x。

### 7. apk 签名与软件源

`files/etc/apk/config` 写着 `allow-untrusted`，装机后 `apk add` 不再校验签名
（等价于每条命令自带 `--allow-untrusted`；apk 只认命令行开关，这个文件是唯一能持久化的位置）。

`files/etc/apk/repositories` 覆盖镜像自带的软件源，只留 PKU 的 immortalwrt 快照 6 条：
`an7581` 目标源 + `aarch64_cortex-a53` 的 base / luci / packages / routing / telephony。
不混用 `downloads.openwrt.org`，避免同名包来自两个快照导致依赖解析打架。

### 8. dummy 接口

`kmod-dummy` 不选中；`diy-ponwrt-full-2.sh` 把 base-files 里 `option name 'dummy0'` 的
device 段整段删掉。

### 9. 工具链缓存

两级缓存，键带 `tools/` `toolchain/` 下所有 `Makefile`/`*.mk` 的哈希：

1. `actions/cache`（正常路径，秒级恢复）
2. Release `toolchain-cache` 里的 `toolchain-airoha-an7581-<hash>.tzst`（LRU 挤掉时的兜底）

命中会跳过 `make tools/install` / `toolchain/install`。首次约 3~5 小时
（含 rust 交叉编译 `airoha-pond`），之后约 40~70 分钟。

## 使用方法

1. 改完推到 `main`，或到 **Actions** 手动触发 **040G-MD 标准版 (PonWrt)**
   （支持 `workflow_dispatch` 与 `repository_dispatch`）。
2. 仓库 **Settings → Actions → General → Workflow permissions** 需为 **Read and write**
   （Release 上传与缓存备份要用）。
3. 完成后到 **Releases** 下载 `040g-md-*.itb`。
4. 需要在构建机调试，Run workflow 时把 `ssh` 填 `true`。

编译依赖用 ponwrt README 那份官方列表（比 P3TERX 模板多 `clang` / `lld` / `llvm` /
`libyaml-dev` / `python3-ply` / `python3-docutils` / `re2c` / `lib32gcc-s1`）。

## 刷机提醒

- 目标是 **UBI** 变体，产物 `sysupgrade.itb`；从原厂固件过来先按 ponwrt 文档确认分区 / U-Boot，
  别在分区布局不明时直接 `sysupgrade`。
- 首启后 `flow_offloading` 已打开，`nft list table bridge fw4` 能看到 `flowtable fb`、
  `/sys/kernel/debug/ppe/bind` 出现 `BND` 条目即为卸载成功。
- `files/etc/shadow` 与 `files/etc/config/network` 里有 **root 密码哈希和 PPPoE 账号密码**。
  仓库若公开，这些会一起公开，建议改私有仓库或换成占位符。
