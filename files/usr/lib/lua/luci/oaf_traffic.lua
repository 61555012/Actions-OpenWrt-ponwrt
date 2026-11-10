-- Hardware-acceleration-safe traffic numbers for the OAF pages.
--
-- OAF's own accounting lives in a netfilter hook: it sees a packet only when
-- the packet walks the stack. Turn on flow offload (nft flowtable) or let the
-- Airoha PPE take the flow over, and most packets never do - the pages then
-- show 0 B/s, a frozen "today" total and an hour chart that stops moving,
-- while the line is actually busy. The bytes still end up in conntrack, just
-- later and in batches, which is why the totals eventually catch up and the
-- rates never do.
--
-- oaf-flowd reads conntrack over netlink and smooths those batches into a real
-- rate; it is the one source on this box that stays correct in both modes. So
-- the OAF controllers ask this module for the traffic columns and keep the
-- rest (app names, parental control, visit records) from fwx.
--
-- Everything here degrades to "unavailable" instead of erroring: without
-- oaf-flowd the pages must keep working exactly as before.

local jsonc = require "luci.jsonc"

local STATS  = "/tmp/oaf-flow/stats.json"
local HOURLY = "/tmp/oaf-flow/hourly.json"
-- 厂商表按顺序探测：旧的 tmpfs 文件是早期手工转换的（整条 MAC 或
-- "04:7C:16" 形式的前缀做键，重启就丢）；usr/share 下是随插件安装的
-- 全量平面表（8712 个 OUI 前缀，6 位去冒号十六进制做键），刷机即有。
local VENDOR_FILES = {
	"/usr/share/oaf_status/vendors.json",
	"/tmp/oaf-flow/vendors.json",
}
local WATCH  = "/tmp/oaf-flow/watched"
local STALE  = 45   -- a snapshot older than this means oaf-flowd is gone

local M = {}

local snap, snap_at = nil, 0
local idx, idx_src = nil, nil
local touched_at = 0

local function read_json(path)
	local f = io.open(path, "r")
	if not f then
		return nil
	end
	local raw = f:read("*a")
	f:close()
	if not raw or #raw < 2 then
		return nil
	end
	local ok, obj = pcall(jsonc.parse, raw)
	if not ok or type(obj) ~= "table" then
		return nil
	end
	return obj
end

-- oaf-flowd keeps sampling at 1 Hz while the marker file is fresh. The LuCI page
-- is exactly the "somebody is looking" case, so bump it - at most once a
-- second, because a single page refresh asks for several endpoints.
local function mark_watched()
	local now = os.time()
	if now - touched_at < 1 then
		return
	end
	touched_at = now
	local f = io.open(WATCH, "w")
	if f then
		f:write("1")
		f:close()
	end
end

-- One parse per request is enough: a page load hits the dashboard, the user
-- list and the top-8 endpoint within the same second.
function M.snapshot()
	local now = os.time()
	if snap and now - snap_at < 1 then
		return snap
	end
	snap_at = now
	local s = read_json(STATS)
	if s and (not s.updated or now - s.updated > STALE) then
		s = nil
	end
	snap = s
	if s then
		mark_watched()
	end
	return s
end

function M.ready()
	return M.snapshot() ~= nil
end

local function build_index(s)
	local m = {}
	for _, c in ipairs(s.clients or {}) do
		local key = (c.mac or c.key or ""):upper()
		-- an IP key means oaf-flowd could not tie the bytes to a MAC; OAF keys
		-- everything by MAC, so those rows are of no use here
		if key:match("^%x%x:") then
			m[key] = {
				ip        = c.ip or "",
				name      = c.name or "",
				rate_up   = c.rate_up or 0,
				rate_down = c.rate_down or 0,
				today_up   = (c.day_up or 0) + (c.live_up or 0),
				today_down = (c.day_down or 0) + (c.live_down or 0),
				-- 今天有流量累计了多少秒。fwx 的那个值在本固件上是个常数，
				-- 采样器自己数，页面才有东西可更新。
				day_active = c.day_active or 0,
				-- 今天"接到网络"了多少秒（conntrack 有流，或 br-lan 上有
				-- reachable 的 ARP 邻居，空闲设备也算）。flowd 1.9.2+；
				-- 旧版本没有该字段读 0。
				day_online = c.day_online or 0,
				-- IPv6 side of the same device: the counters are an exact
				-- share of the totals above (a flow is entirely one family),
				-- and ip6 is the one address worth showing
				ip6        = c.ip6 or "",
				ip6_list   = c.ip6_list,
				rate_up6   = c.rate_up6 or 0,
				rate_down6 = c.rate_down6 or 0,
				today_up6   = (c.day_up6 or 0) + (c.live_up6 or 0),
				today_down6 = (c.day_down6 or 0) + (c.live_down6 or 0),
				-- 采样器看到的实时连接条数（conntrack 里该设备的 flow 行数）。
				-- index 随 snapshot 缓存（1 秒），连接数跟着速率同节奏刷新。
				flows = c.flows or 0,
			}
		end
	end
	return m
end

function M.index()
	local s = M.snapshot()
	if not s then
		return nil
	end
	if idx_src ~= s then
		idx, idx_src = build_index(s), s
	end
	return idx
end

function M.client(mac)
	local index = M.index()
	if not index or not mac then
		return nil
	end
	return index[(mac or ""):upper()]
end

-- 每客户端的 24 小时流量桶（hourly.json，5 秒一刷）。与今日总量在
-- Account() 里同一处记账、重启可从 day.json 恢复，小时之和就是 stats.json
-- 的 day_up/day_down。fwx 的小时流量挂在 netfilter 钩子上：oafd 重启就
-- 清零（今天 09:27 重启后柱状图只剩 1.5MB，而设备实际下行 154M），
-- 硬件卸载的流量也记不全，所以详情页的今日流量柱状图改用这里的数据。
local HOURLY = "/tmp/oaf-flow/hourly.json"

-- whole-LAN picture: today's bytes and the current speed, in bytes
function M.totals()
	local s = M.snapshot()
	if not s then
		return nil
	end
	return {
		up        = s.total_up or 0,
		down      = s.total_down or 0,
		rate_up   = s.rate_up or 0,
		rate_down = s.rate_down or 0,
		updated   = s.updated or 0,
	}
end

-- today's 24 hourly buckets, whole LAN; index is hour + 1
local hour_cache, hour_at = nil, 0

function M.hours()
	-- one parse per request is the point; the age check is for the case where
	-- the module outlives a request (rpc/ucode keeps it loaded), so the chart
	-- can never stick on a payload from an hour ago
	local now = os.time()
	if hour_cache and now - hour_at < 5 then
		return hour_cache[1], hour_cache[2]
	end
	local h = read_json(HOURLY)
	if not h or type(h.hours) ~= "table" then
		return nil
	end
	hour_cache = { h, h.hours }
	hour_at = now
	return h, h.hours
end

-- today's 24 hourly buckets for one client, or nil when it moved nothing
function M.client_hours(mac)
	local h = M.hours()
	if not h or not mac then
		return nil
	end
	local want = (mac or ""):upper()
	for _, c in ipairs(h.clients or {}) do
		if (c.mac or c.key or ""):upper() == want then
			return c.hours
		end
	end
	return nil
end

-- daily totals from oaf-flowd's own day files: [[date, up, down], ...], oldest
-- first. Empty when the directory is missing.
function M.days(limit)
	limit = limit or 30
	local p = io.popen("ls -1 /etc/oaf/data/day 2>/dev/null | sort | tail -n " .. tonumber(limit))
	if not p then
		return {}
	end
	local out = {}
	for name in p:lines() do
		local date = name:match("^(%d%d%d%d%-%d%d%-%d%d)%.json$")
		if date then
			local f = read_json("/etc/oaf/data/day/" .. name)
			if f then
				local up, down = 0, 0
				for _, c in ipairs(f.clients or {}) do
					up = up + (c.day_up or 0)
					down = down + (c.day_down or 0)
				end
				out[#out + 1] = { date = date, up = up, down = down }
			end
		end
	end
	p:close()
	table.sort(out, function(a, b) return a.date < b.date end)
	return out
end

-- Vendor table: oaf-flowd owns the IEEE prefix list and publishes the entry for
-- every device it has seen, so a page only needs the few dozen rows it shows
-- instead of the 40k line registry. Cached for a while: the answer for a given
-- MAC cannot change.
local vendors, ven_at = nil, 0

local function mac_key(mac)
	local s = tostring(mac or ""):upper():gsub("%-", ":")
	return s
end

function M.vendors()
	local now = os.time()
	if vendors and now - ven_at < 20 then
		return vendors
	end
	ven_at = now
	for _, path in ipairs(VENDOR_FILES) do
		local v = read_json(path)
		if v and type(v.macs) == "table" and next(v.macs) then
			vendors = v.macs
			return vendors
		end
	end
	vendors = nil
	return nil
end

function M.vendor(mac)
	local m = M.vendors()
	if not m then
		return nil
	end
	local full = mac_key(mac)
	-- 三种键形态都兼容：整条 MAC（旧 tmpfs 手工表）、"04:7C:16"（冒号
	-- 前缀）、"047C16"（平面表的 6 位十六进制）。命中即返回。
	local v = m[full]
	if v == nil then
		v = m[full:sub(1, 8)]
	end
	if v == nil then
		v = m[(full:gsub(":", "")):sub(1, 6)]
	end
	return v
end

-- 无线客户端信息（信号强度 / 协商速率 / 频段），ubus -> libiwinfo。
-- fwx(oafd) 活着的时候它也提供同样的字段；它不在（appfilter 未装、
-- oafd 挂了）时这是唯一来源——没有它，列表页的信号列整列消失、详情页
-- 的无线信息一栏全空。结果缓存 6 秒；没有无线（或驱动没有 iwinfo 胶水）
-- 的机器只会得到空表和 support=false，页面照常降级。
local wl_cache, wl_at, wl_support = nil, 0, nil
local wl_band, wl_band_at = {}, 0

local function ubus_json(args)
	local p = io.popen("ubus call " .. args .. " 2>/dev/null")
	if not p then
		return nil
	end
	local out = p:read("*a")
	p:close()
	if out and out ~= "" then
		local ok, j = pcall(jsonc.parse, out)
		if ok then
			return j
		end
	end
	return nil
end

local function device_band(dev)
	-- radio 的频段不重新配置就不会变，缓存 10 分钟；按频率判：
	-- < 3GHz 是 2.4G，到 ~5.9GHz 是 5G，再往上 6G
	local now = os.time()
	if wl_band[dev] and now - wl_band_at < 600 then
		return wl_band[dev]
	end
	local info = ubus_json(string.format("iwinfo info '%s'", dev))
	local band
	if info and tonumber(info.frequency) then
		local mhz = tonumber(info.frequency)
		if mhz < 3000 then
			band = "2g"
		elseif mhz < 5900 then
			band = "5g"
		else
			band = "6g"
		end
		wl_band[dev] = band
		wl_band_at = now
	end
	return band
end

-- map[MAC] = { rssi, tx_rate, rx_rate, ifname, band }。速率单位 kbit/s，
-- 与 fwx 一致（前端除以 1000 显示 Mbit/s）。apcli*/apclix* 是中继模式的
-- 上联口，不会挂我们的局域网客户端，跳过。
function M.wireless()
	local now = os.time()
	if wl_cache and now - wl_at < 6 then
		return wl_cache, wl_support
	end
	wl_at = now
	local out, support = {}, false
	local devices = ubus_json("iwinfo devices")
	for _, dev in ipairs((type(devices) == "table" and devices.devices) or {}) do
		if type(dev) == "string" and dev:sub(1, 5) ~= "apcli" then
			support = true
			local band = device_band(dev)
			local al = ubus_json(string.format("iwinfo assoclist '%s'", dev))
			for _, st in ipairs((al and al.results) or {}) do
				local mac = tostring(st.mac or ""):upper()
				if mac ~= "" then
					out[mac] = {
						rssi    = tonumber(st.signal),
						tx_rate = st.tx and tonumber(st.tx.rate) or nil,
						rx_rate = st.rx and tonumber(st.rx.rate) or nil,
						ifname  = dev,
						band    = band,
					}
				end
			end
		end
	end
	wl_cache, wl_support = out, support
	return out, support
end

-- 列表页信号列的开关（get_system_base_info 的 wireless_support 兜底）
function M.wireless_support()
	M.wireless()
	return wl_support
end

-- 单个客户端的无线信息；不在任何 radio 的 assoclist 里（有线设备）返回 nil
function M.wireless_user(mac)
	local w = M.wireless()
	if not w or not mac then
		return nil
	end
	return w[mac_key(mac)]
end

-- A link-local address only repeats the MAC in another notation, so it is
-- never worth a row of its own.
local function is_link_local(a)
	return tostring(a):lower():sub(1, 5) == "fe80:"
end

-- Last resort for the address: fwx keeps the IPv6 a device used last in
-- /proc/net/af_client, which still says something when oaf-flowd has no row for
-- that device (idle all day) or is not running.
local AF = "/proc/net/af_client"
local af6, af_at = nil, 0

local function af_client_v6()
	local now = os.time()
	if af6 and now - af_at < 5 then
		return af6
	end
	af_at = now
	af6 = {}
	local f = io.open(AF, "r")
	if not f then
		return af6
	end
	f:read("*l")
	for line in f:lines() do
		local mac, v6 = line:match("^%s*%d+%s+(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s+%S+%s+(%S+)")
		if mac and v6 and v6 ~= "::" and not is_link_local(v6) then
			af6[mac:upper()] = v6
		end
	end
	f:close()
	return af6
end

-- The single IPv6 address a page should show. oaf-flowd ranks them already - a
-- global address beats a ULA or link-local one, and among equals the one used
-- most recently wins - so its first entry is the answer; anything link-local
-- is skipped, because it adds nothing next to the MAC that is already shown.
function M.ip6(mac)
	local c = M.client(mac)
	if c then
		if type(c.ip6_list) == "table" then
			for _, a in ipairs(c.ip6_list) do
				if not is_link_local(a) then
					return a
				end
			end
		end
		if c.ip6 ~= "" and not is_link_local(c.ip6) then
			return c.ip6
		end
	end
	local key = mac_key(mac)
	if key ~= "" then
		return af_client_v6()[key]
	end
	return nil
end

-- Overlay oaf-flowd's numbers on one user row from fwx. Only the traffic columns
-- and a placeholder address are touched, so the caller keeps every other
-- field exactly as OAF produced it.
function M.merge_user(u)
	if type(u) ~= "table" then
		return u
	end
	local v = M.vendor(u.mac)
	if v then
		u.vendor = v
	end
	local ip6 = M.ip6(u.mac)
	if ip6 then
		-- two names for the same address: the list draws its own second line,
		-- the detail page already has a field called ipv6 from fwx, and both
		-- should agree on which of the device's addresses that is
		u.ip6 = ip6
		u.ipv6 = ip6
	end
	local c = M.client(u.mac)
	if not c then
		return u
	end
	-- The plain columns stay the whole truth for every consumer that is not
	-- the user list (the dashboard shows one speed per device, not a pair).
	-- The *6 fields are the IPv6 share, so the list can split the row.
	u.up_rate = c.rate_up
	u.down_rate = c.rate_down
	-- 实时连接条数（conntrack 里该设备的 flow 行数），列表页的「连接数」
	-- 列在慢通道首次渲染用它，之后由 live_rates 快通道每秒刷新。
	u.flows = c.flows or 0
	u.today_up_bytes = c.today_up
	u.today_down_bytes = c.today_down
	-- 上网时长用采样器的 day_active：1.8.0 起它是"活跃秒数"口径——某一
	-- 轮采样里这条设备真的搬了字节（超过心跳阈值）才算时间，挂机的 QQ/
	-- 微信/输入法长连接不再贡献时长。flowd 是权威口径，0 就是「这一天
	-- 还没真正用过」，不透传 fwx 的粗采样值（手机没开屏只有 4 分钟、
	-- 挂机长连接又能推到 100+ 分钟，两头都不对）。设备不在采样器里
	-- （刚接入、tmpfs 过期）时保持 fwx 原值。
	u.today_active_time = c.day_active or 0
	-- 今日在线时长 = 设备接到网络的墙钟时间，必然 >= 上网时长。
	-- fwx（oafd）在时它给的是会话口径，flowd 给的是在网口径，两者取大的；
	-- 两者都没有（旧采样器、刚接入）时，用上网时长兜底——上过网的每一秒
	-- 一定是在网的，绝不能出现「上网 59m / 在线 3m」这种倒挂。
	-- 之前只在 fwx 值为 0 时才用 flowd，重启后 flowd 的在线计数重新从 0
	-- 起算、上网时长却从日文件恢复，于是一直被这个 0 挡住。
	local online = tonumber(u.today_online_time) or 0
	if (c.day_online or 0) > online then online = c.day_online end
	if (c.day_active or 0) > online then online = c.day_active end
	u.today_online_time = online
	u.up_rate6 = c.rate_up6
	u.down_rate6 = c.rate_down6
	u.today_up6_bytes = c.today_up6
	u.today_down6_bytes = c.today_down6
	-- 快照的 ip 字段可能装着 IPv6（设备当天只有 v6 流）；IP 列只认
	-- IPv4 租约，v6 有自己的行，别把一长串全球地址填进这一格。
	if c.ip ~= "" and not c.ip:find(":", 1, true)
		and (u.ip == nil or u.ip == "" or u.ip == "0.0.0.0") then
		u.ip = c.ip
	end
	if c.name ~= "" and (u.hostname == nil or u.hostname == "") then
		u.hostname = c.name
	end
	return u
end

-- Same, for a whole list (user list, active users, top users).
function M.merge_list(list)
	if type(list) ~= "table" or not M.ready() then
		return false
	end
	for _, u in ipairs(list) do
		M.merge_user(u)
	end
	return true
end

-- Per-app traffic for one client. Source is oaf-flowd's apps.json:
--   { clients = { mac = { {id=3003, up=.., down=.., h={[23]={up,down}}}, .. } } }
--
-- This is the one app number that survives flow offload: the app id rides on
-- the conntrack mark (written when the flow was classified) and the bytes are
-- the conntrack counters, which the PPE driver keeps writing back. fwx's own
-- per-app stats come from the netfilter hook, so they stop the moment a flow
-- is offloaded - that is why the top-apps chart only ever showed the first
-- few packets of a long connection.
local APPS = "/tmp/oaf-flow/apps.json"
local apps_cache, apps_at = nil, 0

function M.app_traffic(mac)
	if not mac or mac == "" then
		return nil
	end
	local now = os.time()
	if not apps_cache or now - apps_at >= 2 then
		apps_at = now
		local s = read_json(APPS)
		if not s or (s.updated and now - s.updated > STALE) then
			apps_cache = {}
		else
			apps_cache = s.clients or {}
		end
	end
	return apps_cache[mac:lower()] or apps_cache[mac:upper()] or {}
end

-- Per-app ACTIVE seconds for one client, from apps.json's "a" field
-- (oaf-flowd 1.8.0+). This is what the APP-duration charts should show:
--   { [appid] = total_seconds, hours = { [hour] = { [appid] = seconds } } }
-- An app that only holds an idle keep-alive connection never shows up here,
-- while one that actually carries data accumulates one tick per sample round.
-- Returns nil when the sampler has no usable data for today.
local appact_cache, appact_at = nil, 0

function M.client_app_active(mac)
	if not mac or mac == "" then
		return nil
	end
	local list = M.app_traffic(mac)
	if type(list) ~= "table" or #list == 0 then
		return nil
	end
	local total, hours = {}, {}
	local any = false
	for _, a in ipairs(list) do
		local sum = 0
		local h = a.a
		if type(h) == "table" then
			for hour, sec in pairs(h) do
				sec = tonumber(sec) or 0
				if sec > 0 then
					any = true
					sum = sum + sec
					local row = hours[tonumber(hour)]
					if not row then
						row = {}
						hours[tonumber(hour)] = row
					end
					row[tonumber(a.id)] = (row[tonumber(a.id)] or 0) + sec
				end
			end
		end
		if sum > 0 then
			total[tonumber(a.id)] = sum
		end
	end
	if not any then
		return nil
	end
	return { apps = total, hours = hours }
end

-- Flow offload as the firewall config sees it. Read, not parsed by uci: this
-- runs on every dashboard refresh and must not fork.
function M.accel()
	local f = io.open("/etc/config/firewall", "r")
	if not f then
		return false
	end
	local raw = f:read("*a") or ""
	f:close()
	return raw:match("option%s+flow_offloading%s+['\"]?1") ~= nil
end

return M
