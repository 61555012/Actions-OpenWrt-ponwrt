# Actions-OpenWrt-PonWrt (Nokia XG-040G-MD)

用 GitHub Actions 云编译 **Nokia XG-040G-MD (UBI)**（`airoha/an7581`，内核 6.18）固件。
源码树是 [pbs05/ponwrt](https://github.com/pbs05/ponwrt) `master`，仓库里只保留**一条**标准版流水线。

> 2026-11 清理：mosdns 分流（含 Go 工具链与 v2ray-geodata）、OAF 的 **LuCI 界面**
> （`luci-app-oaf`：前端页面 / 控制器）、以及整条「纯净版 / Lite」编译链路都已删除。
> 这些包在 `.config-ponwrt-full` 里显式写成 `is not set`，工作流编译前还有 `absent()` 断言，
> 不会被官方基线或 feeds 默认值带回来。
>
> 2026-11 新增：「状态 → 用户列表」(`oaf_status`)。这是自建插件（从 S20P 机型整包搬来），
> 与上面那个第三方 `luci-app-oaf` 界面无关，包含 Lua 版 controller/CBI/view、`oaf-flowd` 采样器、
> OUI 厂商库与 562 个应用图标。PonWrt 本身是纯 ucode 版 LuCI，没有 Lua 解释器，所以
> `.config-ponwrt-full` 里重新打开了 `luci-compat` / `luci-lib-jsonc` / `luci-lib-nixio` /
> `ucode-mod-lua` —— 少任何一个，页面都会 404 或整棵页面树构建失败。
>
> 2026-11 补齐：**OAF 识别内核** `kmod-oaf` + `appfilter`（`oafd`）。这是用户列表里
> APP 名称、访问记录、APP 时长的唯一数据源：`oaf.ko` 在 conntrack 写应用标记并导出
> `/proc/net/af_*`，`oafd` 维护 `/tmp/oaf/client.db`，`oaf-flowd` 再从这份库滚动出 30 天访问历史。
> 只装内核和守护，`luci-app-oaf` 界面仍然删掉（diy-part2 里 `rm -rf`），否则会出现第二套重复菜单。
> 统计目录固定为 overlay 的 `/etc/oaf/data`，**不再使用任何 `/mnt/mmcblk*` 外挂分区**。

## 目录

```
.github/workflows/build-040g-ponwrt-full.yml   # 唯一的工作流
.github/workflows/update-checker.yml           # 上游源码更新时触发 repository_dispatch
.config-ponwrt-full                            # 叠加层：只写官方基线之外要加/要关的包与开关
diy-ponwrt-full-1.sh                           # feeds update 之前：替换/追加 feed
diy-ponwrt-full-2.sh                           # feeds update 之后：内核每流统计、PPE FIN 老化补丁、NPU 面板、去 dummy
diy-ponwrt-full-3.sh                           # feeds install 之后：argon v3.1.1 覆盖 feeds 旧版
files/                                         # 原样合并进固件根目录
  etc/config/{network,pon,firewall,upnpd,onu-internet}  # 实机配置（PPPoE、光猫注册、UPnP、加速开关）
  etc/shadow                                 # root 密码
  etc/internet.nft / etc/iptv.nft            # wanup / IPTV 桥接规则（firewall include 引用）
  etc/apk/config                             # apk 信任配置：allow-untrusted
  etc/uci-defaults/99-040g-md                # 首启：加速开关 / 去 dummy / 主题 / OMCC 版本
  etc/uci-defaults/99-oaf-status-defaults    # 首启：预建统计目录 + 启用采样器
  etc/init.d/oaf-flowd                       # 采样器 procd 服务（每次拉起重建 day/ mon/）
  usr/sbin/oaf-flowd                         # 用户列表采样器（aarch64 静态 ELF）
  usr/lib/lua/luci/controller/oaf_status_users.lua   # 用户列表/详情路由 + 全部 API
  usr/lib/lua/luci/{model/cbi,view}/oaf_status/*     # 列表页与详情页
  usr/lib/lua/luci/oaf_traffic.lua           # 采样器快照合并（V4/V6 分行、厂商名）
  usr/share/oaf_status/vendors.json          # OUI 厂商库
  www/luci-static/resources/oaf_status/      # 前端资源（jquery / echarts / 562 个应用图标）
  www/luci-static/resources/oui/             # OUI 品牌图标库
  usr/share/rpcd/ucode/luci                  # getCPUUsage 改为实时采样（扣除采样器自身占用）
  www/luci-static/resources/view/status/include/10_system.js  # overview 的 CPU 行 3 秒轮询
```

## 编译出来的东西

| 项目 | 说明 |
|---|---|
| 目标 | `airoha/an7581` → `nokia_xg-040g-md-ubi`，产物 `sysupgrade.itb` |
| 硬件加速 | fw4 生成 `inet` + `bridge` 两张 flowtable，L3 与 **L2 桥接**都下到 Airoha PPE；默认 `flow_offloading=1` |
| 每流统计 | `CONFIG_NET_AIROHA_FLOW_STATS=y`（即 `airoha_ppe_foe_flow_stats_*` / `FLOW_CLS_STATS`），编译后会复查生成的内核 `.config` |
| PPE FIN 老化 | `delta_tcp_fin` 由 1s 改 30s，保证卸载流的尾部字节能被 conntrack 回写采到 |
| PON / 光模块 | `kmod-airoha-xpon` + `kmod-airoha-pon-frontend` + `kmod-airoha-en7572`（EN7572 光前端）+ `airoha-pond` / `airoha-ponctl`，**全部强制 `=y`** |
| 2.5G 网口 | `kmod-phy-airoha-en8811h` + `airoha-en8811h-firmware`，**强制 `=y`**（lan1，`2500base-x` 链路） |
| UPnP | `miniupnpd-nftables` + `luci-app-upnp`（fw4 是 nftables，必须 nftables 变体） |
| 其他插件 | `luci-app-onu` + `luci-app-pon-status`（[naoki66/OpenWrt_ONU_CONFIG](https://github.com/naoki66/OpenWrt_ONU_CONFIG)）、`luci-app-airoha-npu`（[luanmuc](https://github.com/luanmuc/luci-app-airoha-npu)）、`argon v3.1.1` |
| OMCI 兼容性 | `omcc_version` 默认 **`0x86`**（见「5. OMCC 版本」） |
| CPU 占用 | overview 的 `CPU usage (%)` 改为 `/proc/stat` 增量采样，3 秒刷新，已扣除采样器自身开销（见「9.」） |
| 去除项 | dummy 接口（`kmod-dummy` 不选 + 构建期删 base-files 模板 + 首启 uci 清理） |

## 关键设计说明

### 1. 配置策略：官方基线 + 叠加层

`.config-ponwrt-full` **不是**完整配置。构建时先做：

```sh
./scripts/kconfig.pl + configs/an7581.config configs/release.config > .config   # 官方基线
sed -i '/^CONFIG_TARGET_DEVICE_airoha_an7581_DEVICE_/d' .config                # 只留本机
echo 'CONFIG_TARGET_DEVICE_airoha_an7581_DEVICE_nokia_xg-040g-md-ubi=y' >> .config
cat 仓库/.config-ponwrt-full >> .config                                       # 叠加层
make defconfig
```

官方 `configs/an7581.config`（约 8900 行）里带着 UBIFS 大小、squashfs 块大小、initramfs、内核参数等**镜像级设置**，手写种子缺了这些很容易编出起不来的镜像，所以直接拿它当底，只把别的机型删掉。设备名里的横杠在 CONFIG 符号里是**保留**的。

### 2. PON 用户态换源（必须替换，不能追加）

`naoki66/OpenWrt_ONU_CONFIG` 是 `pbs05/openwrt-pon-userspace` 的深度 fork，包名（`airoha-pond`、`airoha-ponctl`）与上游**完全重叠**，同时把 `luci-app-pon` 升级为顶级 `luci-app-onu` 并吸收了 `luci-app-iptv`。所以 `diy-ponwrt-full-1.sh` 直接把 `feeds.conf.default` 里的 `pon_userspace` 源**替换**掉；追加会导致 `feeds install` 同名包冲突。`pon_drivers`（xPON MAC + 光前端）保持上游官方源。

### 3. 每流统计为什么不在 `.config-ponwrt-full` 里

`CONFIG_NET_AIROHA_FLOW_STATS` 是**内核 Kconfig** 符号（`depends on NET_AIROHA && NET_AIROHA_NPU`，两者在 `config-6.18` 里都是 `=y`），不是 OpenWrt 包符号。所以只能改 `target/linux/airoha/an7581/config-6.18`（原文件是 `# ... is not set`），由 `diy-ponwrt-full-2.sh` 完成，并在编译后再核对一次 `build_dir/.../linux-*/.config`。

关掉它，`airoha_ppe_foe_entry_get_stats()` 直接返回 0，被 PPE 卸载的流在 conntrack 里字节数不涨；这是平台级开关，与是否装上层统计插件无关，因此保留。

### 4. 硬件加速与统计的取舍

PPE 卸载后报文不再经过 netfilter，conntrack 里的字节数只能靠驱动周期性回写拿到。本固件默认 `flow_offloading=1`（`files/etc/config/firewall`）；完全关闭加速可以让软件侧逐包记账，但会损失全部硬件转发性能：

```sh
uci set firewall.@defaults[0].flow_offloading='0'
uci set firewall.@defaults[0].flow_offloading_hw='0'
uci commit firewall && /etc/init.d/firewall reload
```

#### 4.1 PPE 条目在 TCP FIN 后的老化时间（1s → 30s）

`airoha_ppe_hw_init()` 里 `PPE_BIND_AGE1` 的 `delta_tcp_fin` 上游取 **1 秒**（`delta_tcp` 是 60 秒）。收到 FIN 的流由硬件按它老化，也就是最后一个包之后约 1 秒条目就从 PPE 表里消失。

这和流量统计**是同一件事**：

- 报文下到 PPE 后，conntrack 的字节数靠 `nf_flow_table` → `FLOW_CLS_STATS` → `airoha_ppe_flow_offload_stats()` → `airoha_ppe_foe_entry_get_stats()` 定期回写累加。
- `FLOW_CLS_DESTROY`（`airoha_ppe_flow_offload_destroy()`）**只删条目，不取最后一次计数**，移除时还会把 stats 槽清零。
- 条目一旦先被硬件回收，下一次 stats 轮询就查不到 hash，尾部这一截字节永久丢失——**秒级结束的大流量丢得最狠**。

`diy-ponwrt-full-2.sh` 会往 `target/linux/airoha/patches-6.18/700-net-airoha-ppe-raise-tcp-fin-age.patch` 写一个补丁，把 `delta_tcp_fin` 改成 **30 秒**；编译后的 `Verify built kernel config` 步骤复查内核源码里的实际值，没生效直接判失败。

- **效果**：条目能活到下一次 stats 轮询之后再回收，conntrack 累计值不再丢尾部字节。
- **代价**：已结束的连接多占 30 秒槽位（表 16K 槽，家用几百条流，无压力），TCP 常态老化 60s 不变。
- **验证**：刷完 `devmem 0x1FB50E40 32` 读到的就是初始化时锁存的实际值——`0x001E003C` = FIN 30s / TCP 60s（补丁生效），`0x0001003C` = 源码默认 1 秒。运行中把寄存器写回去**无效**，只能改源码重编。
- **撤销**：把补丁里的 `30` 改回 `1`，或整段 heredoc 删掉。

#### 4.2 删掉 LuCI 的「系统 → 插件」页

这一页来自 `luci-mod-system` 的 luci-plugins 框架：视图 `view/system/plugins.js` + 菜单项 `admin/system/plugins`。它只扫描 `/www/luci-static/resources/view/plugins/*.js` 里的插件定义，本固件那个目录是**空的**，点进去只有一张空表和一个「全局设置」开关。`diy-ponwrt-full-2.sh` 在 `feeds update` 之后、`feeds install` 之前把视图删掉、把菜单项从 `luci-mod-system.json` 里摘掉（python3 改 JSON，无 python3 时退回 sed），所以编出来的固件里没这一页。

#### 4.3 关掉 apk 的安装签名要求

apk（apk-tools 3）只装签名能被 `/etc/apk/keys/` 里公钥验证的包，装自编译 / 第三方 .apk 会直接报 `UNTRUSTED signature`。全局开关只有一条：`files/etc/apk/config` 里的 `allow-untrusted`（**它是无参数开关**，写成 `allow-untrusted=yes` 只会得到一条 warning 并被忽略）。

```sh
apk add /tmp/x.apk              # ERROR: /tmp/x.apk: UNTRUSTED signature
printf 'allow-untrusted\n' > /etc/apk/config
apk add /tmp/x.apk              # 签名这道关卡不再拦
```

### 5. OMCI 设置 → 兼容性 → OMCC 版本 = 0x86

LuCI「网络 → ONU → 设置 → 兼容性」里的 `omcc_version` 决定 ONU 向 OLT 声明的 OMCI 基线，可选值为 `0x86 / 0xa0 / 0xa8 / 0xb0 / 0xb4`，上游页面默认是 `0xb0`。本仓库改成 **`0x86`**（兼容不认老旧/第三方 ONU 的华为 OLT），两处一起改：

1. `files/etc/config/pon` 的 `option omcc_version '0x86'` —— 出厂配置，全新刷机即生效。
2. `files/etc/uci-defaults/99-040g-md` 遍历所有 `omci` 段写一次 `0x86` —— 升级刷机时 `/etc/config/pon` 会被保留，光改出厂配置不够。

工作流编译前会校验 `files/etc/config/pon` 里的值，不是 `0x86` 直接失败。

### 6. argon 为什么要单独一个 diy-ponwrt-full-3

feeds（immortalwrt/luci）里自带同名 `luci-theme-argon`。如果在 `feeds install` **之前**删掉 feeds 目录，install 会留下悬空链接/报错；所以放到 install **之后**：删 `package/feeds/luci/luci-theme-argon` 软链 → 删 `feeds/.../luci-theme-argon` 目录 → 克隆 v3.1.1 到 `package/luci-theme-argon`，并断言版本号是 3.x。

### 7. dummy 接口

`kmod-dummy` 不选中；`diy-ponwrt-full-2.sh` 把 base-files 里 `option name 'dummy0'` 的 device 段整段删掉；首启 uci-defaults 再兜底清理 `network` 里所有 dummy 段，已刷过旧固件升级上来的同样会清干净。

### 8. 工具链缓存

两级缓存，键里带 `tools/` `toolchain/` 下所有 `Makefile`/`*.mk` 的哈希：

1. `actions/cache`（正常路径，秒级恢复）
2. GitHub Release `toolchain-cache` 里的 `toolchain-airoha-an7581-<hash>.tzst`（缓存被 LRU 挤掉时的兜底）

缓存命中会自动跳过 `make tools/install` / `toolchain/install`，并用 `sed` 去掉主 `Makefile` 里的 toolchain 依赖。首次约 3~5 小时（含 rust 交叉编译 `airoha-pond`），之后约 40~70 分钟。删掉 mosdns 后不再编译 Go 工具链，首次构建比之前快。

### 9. overview 的 CPU 占用改成实时采样

上游 `getCPUUsage`（`/usr/share/rpcd/ucode/luci`）是：

```sh
popen('top -n1 | awk \'/^CPU/ {printf("%d%", 100 - $8)}\'')
```

busybox `top -n1` 单次运行的取样窗口只有约 0.1 秒，而 **fork `top` + ubus 往返本身就要吃掉这段时间的一部分**，所以空闲时也恒定显示 3~5%：既不归零，也不随实际负载变化（4 核实测：空闲 3%、1 核满载 25%，前者是假的）。`100 - $8` 还硬编码了字段位置。

改成纯 ucode 的两点差分：

- 相邻两次调用之间各读一次 `/proc/stat`（前端 3 秒轮询一次，窗口就是 3 秒），不 fork 进程、不解析文本；
- **再扣掉采样器自己的占用**：`/proc/self/stat` 的 `utime+stime+cutime+cstime` 增量（ucode 方法在 rpcd 进程内执行，`comm` 用 `rindex(s,')')` 跳过），`busy = (dt - di) - ds` 后夹到 `[0, dt]`。不扣的话，每次测量动作的 5~8 ticks 会把它顶成 1~2% 的固定读数；
- 距上次采样超过 10 秒（关掉页面后又打开）丢弃缓存，退化为一次 200ms 短采样，保证首屏是当前值而不是长期平均。

`files/www/luci-static/resources/view/status/include/10_system.js` 里给 `CPU usage (%)` 那一格加 `poll.add(fn, 3)`，只更新单元格本身；回调先查 `el.isConnected` / `el.offsetParent` / `document.hidden`，DOM 不在或标签页隐藏就直接返回，**不发 RPC**。LuCI 的 `poll` 是全局队列、切视图不清空、也没有 `document.hidden` 判断，所以这层判断必须自己加，否则离开页面后仍在后台每 3 秒打一次。

实测（4 核，`yes` 占满 N 核后取稳定的 3 秒窗口）：空闲 **0%**，1/2/3/4 核分别 **25% / 50% / 75% / 100%**，撤掉负载回到 0%；真实 `HTTP → /ubus` 路径连续轮询全部 `0%`。页面上只显示纯百分比（如 `0%`），不带 `CPU:` 之类前缀——与 S20P 仓库的同一改动保持一致。

> 这两个文件是**整文件覆盖**上游（rpcd 的 ucode 脚本由 luci-base 提供，overview 视图由 luci-mod-status 提供）。上游大版本更新这两个文件后需要重新对一次；工作流编译前会校验它们确实是本仓库的实时采样版本，缺失或退回 `top` 实现会直接失败。

## 使用方法

1. 改完代码直接推到 `main`，或到 **Actions** 里手动触发 **040G-MD 标准版 (PonWrt)**（支持 `workflow_dispatch` 与 `repository_dispatch`）。
2. 仓库 **Settings → Actions → General → Workflow permissions** 需为 **Read and write**（Release 上传与缓存备份要用）。
3. 完成后到 **Releases** 下载 `040g-md-*.itb`。
4. 需要进构建机调试，Run workflow 时把 `ssh` 填 `true`（action-tmate）。

> 编译依赖用 ponwrt README 那份官方列表（比 P3TERX 模板多 `clang` / `lld` / `llvm` / `libyaml-dev` / `python3-ply` / `python3-docutils` / `re2c` / `lib32gcc-s1`）。

## 刷机提醒

- 目标是 **UBI** 变体，产物为 `sysupgrade.itb`；从原厂固件过来请先按 ponwrt 文档确认分区/U-Boot，别在分区布局不明时直接 `sysupgrade`。
- 首启后 `flow_offloading` 已打开，`nft list table bridge fw4` 能看到 `flowtable fb`、`/sys/kernel/debug/ppe/bind` 出现 `BND` 条目即为卸载成功。
- `files/etc/shadow` 与 `files/etc/config/network` 里有 **root 密码哈希和 PPPoE 账号密码**。仓库若是公开的，这些会一起公开，建议改成私有仓库，或把这两处换成占位符。
