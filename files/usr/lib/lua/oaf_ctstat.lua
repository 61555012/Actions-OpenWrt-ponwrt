-- oaf-ctstat.lua -- hardware-offload-safe accounting for the OAF user pages.
--
-- Why this exists
--   The stock OAF collector (oafd) gets its byte counters from the oaf.ko
--   netfilter hook over a private netlink channel. Once a flow is taken over
--   by the Airoha PPE / nft flowtable, its packets no longer walk the netfilter
--   stack, so the hook only ever sees the first few packets. oafd therefore
--   reports 0 B/s and a frozen "today" total while the line is busy.
--
--   The PPE does write the byte counters back into conntrack (measured
--   writeback period 3.10 s; FIN ageing 30 s covers it), and oaf.ko writes the
--   classified app id into the low 16 bits of the conntrack mark. Both survive
--   offload. This module reads those two official OAF data sources plus
--   /proc/net/af_client (the official MAC table) and settles every flow:
--     * periodic /proc/net/nf_conntrack snapshot -> in-flight long connections
--     * conntrack DESTROY events                -> short-lived flows, no loss
--   It emits the JSON files the S20P LuCI read layer (luci.oaf_traffic)
--   already expects. oafd is left running untouched for control functions,
--   visit records and app names.
--
--   All data is tmpfs (/tmp/oaf-flow), bounded at 10 MiB; a reboot clears
--   everything. Dates/hours are Beijing time (UTC+8) even though the box
--   runs UTC. Sampling is 1 s while a page is being watched, 20 s otherwise.
--   No kernel module, no binary replacement, no config change.

local DIR     = "/tmp/oaf-flow"
-- Everything lives on tmpfs now: a reboot wipes traffic AND app data.
-- No flash writes at all, and "today" always means "since this boot".
local DAYDIR  = DIR .. "/day"
local CT      = "/proc/net/nf_conntrack"
local AF      = "/proc/net/af_client"
local ARP     = "/proc/net/arp"
local EV      = DIR .. "/events.log"
local EVPID   = DIR .. "/events.pid"
local LOCK    = DIR .. "/ctstat.pid"
local WATCH   = DIR .. "/watched"
local LOG     = DIR .. "/ctstat.log"
local STATSF  = DIR .. "/stats.json"
local HOURLYF = DIR .. "/hourly.json"
local APPSF   = DIR .. "/apps.json"
-- 访问记录用的「有流量的访问段」，秒级。和 apps.json 的活跃秒同源：都在
-- settle_round 里按同一个 2 KiB/窗口 门槛判定，所以两处数字必然一致。
local ACTIVEF = DIR .. "/active.json"

local IDLE_SEC   = 20      -- nobody is looking: slow refresh (< read layer's 45 s STALE)
local ACTIVE_SEC = 1       -- somebody is looking: 1 s sampling / 1 s page refresh
local THROTTLE_SEC  = 2    -- but back off to this when the conntrack table is big
local THROTTLE_LINES = 800  -- 800 rows * ~64 us/row ~ 50 ms/round on this SoC
local FULL_SEC   = 10      -- hourly/apps/day are serialised at most this often
local GONE_TTL   = 300     -- keep a vanished flow this long for its DESTROY
local MAC_TTL    = 60      -- refresh MAC ownership this often
-- One sampling window must move at least 2 KiB before it counts as "active".
-- Idle long connections (Sogou IME, QQ, push channels) keep a TCP session up
-- all day on a few hundred bytes of keepalive; without this floor they would
-- report 24 h of "usage". The floor is applied to ONE window, not to the
-- whole connection, so a real transfer still counts from its first window.
local ACTIVE_MIN = 2048
-- 访问段：某设备某应用「真的在传数据」的连续区间。中间断一两轮不算断开
-- （PPE 每 ~3.1 s 才回写一次计数，1 s 采样会看到空洞），超过 GAP_SEC 才算
-- 这次访问结束。挂机心跳一轮只有几百字节，永远到不了 ACTIVE_MIN，因此
-- 根本不会产生段——不必事后过滤。
local GAP_SEC   = 120
local SEG_KEEP  = 2 * 86400
local SEG_MAX   = 200
local CAP_KB     = 10240   -- hard ceiling for the whole data directory (10 MiB)
local CAP_CHECK  = 60      -- check the ceiling this often
local KEEP_DAYS  = 30
local TZ_OFFSET  = 8 * 3600 -- device runs UTC; all buckets/dates are Beijing time

-- os.date("!") is UTC; adding 8 h gives Beijing wall clock regardless of the
-- device's own zonename (which is UTC here). LuCI labels the 0..23 axis with
-- these same buckets, so charts and "today" match what the user sees locally.
local function ldate(fmt, ts)
	return os.date("!" .. fmt, (ts or os.time()) + TZ_OFFSET)
end

-- 1 s sampling needs a sub-second clock. os.time() is whole seconds only,
-- which would make the loop spin several times inside the same second.
-- nixio is part of every OpenWrt Lua install; nanosleep also removes the
-- busybox `sleep` fork that the old 5 s loop paid for once per round.
local nixio_ok, nixio = pcall(require, "nixio")
local function wall()
	if nixio_ok and nixio.gettimeofday then
		local s, us = nixio.gettimeofday()
		return s + us / 1000000
	end
	return os.time()
end
local function nap(sec)
	if not sec or sec <= 0 then return end
	if nixio_ok and nixio.nanosleep then
		local whole = math.floor(sec)
		nixio.nanosleep(whole, math.floor((sec - whole) * 1000000000))
	else
		local whole = math.ceil(sec)
		if whole > 0 then os.execute("sleep " .. whole) end
	end
end

---------------------------------------------------------------- utilities

local function log(fmt, ...)
	local f = io.open(LOG, "a")
	if not f then return end
	f:write(ldate("%Y-%m-%d %H:%M:%S "), string.format(fmt, ...), "\n")
	f:close()
end

local function atomic(path, body)
	local f = io.open(path .. ".tmp", "w")
	if not f then return false end
	f:write(body)
	f:close()
	os.rename(path .. ".tmp", path)
	return true
end

local function num(v)
	return string.format("%d", math.floor(v or 0))
end

local function jstr(s)
	s = tostring(s or "")
	s = s:gsub("\\", "\\\\"):gsub('"', '\\"')
		:gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t")
	return '"' .. s .. '"'
end

-- IPv6 canonical form. /proc/net/nf_conntrack prints expanded addresses
-- (0000:0000:...) while conntrack -E / af_client / ip -6 neigh print
-- compressed ones (::1). Everything is normalised to 8 x 4 lowercase hex.
-- Addresses repeat heavily across rows, so memoise the expansion.
local n6_cache, n6_n = {}, 0
local function n6(s)
	if not s or s:find(":") == nil then return s end
	local hit = n6_cache[s]
	if hit then return hit end
	local orig = s
	s = s:gsub("%%.*$", "")
	if s:find("%.") then return s:lower() end        -- IPv4-mapped, rare
	local head, tail = s:match("^(.-)::(.-)$")
	local parts = {}
	local function split(str, out)
		if not str or str == "" then return end
		for p in str:gmatch("[^:]+") do out[#out + 1] = p end
	end
	if head then
		split(head, parts)
		local tp = {}
		split(tail, tp)
		for _ = 1, 8 - #parts - #tp do parts[#parts + 1] = "0" end
		for _, p in ipairs(tp) do parts[#parts + 1] = p end
	else
		split(s, parts)
	end
	local function put(v)
		if n6_n > 4096 then n6_cache, n6_n = {}, 0 end
		n6_cache[orig] = v
		n6_n = n6_n + 1
		return v
	end
	if #parts ~= 8 then return put(s:lower()) end
	local out = {}
	for i = 1, 8 do
		out[i] = ("0000" .. parts[i]:lower()):sub(-4)
	end
	return put(table.concat(out, ":"))
end

local function new_buckets()
	local t = {}
	for i = 1, 24 do t[i] = { up = 0, down = 0 } end
	return t
end

local function new_client(mac)
	return {
		mac = mac, ip = "", ip6 = "", ip6_list = {},
		up = 0, down = 0, up6 = 0, down6 = 0,
		hours = new_buckets(), apps = {}, hist = {},
		flows = 0, flows6 = 0, active = 0, online = 0,
		rate_up = 0, rate_down = 0, rate_up6 = 0, rate_down6 = 0,
		prev_up = 0, prev_down = 0, prev_up6 = 0, prev_down6 = 0,
		round_bytes = 0, round_apps = {},
	}
end

---------------------------------------------------------------- state

local clients = {}          -- [MAC] = client record
local segs    = {}          -- [MAC] = { {id, ft, lt}, ... } 有流量的访问段
local flows   = {}          -- [tuple key] = per-flow byte baseline
local retired = {}          -- [tuple key] = baseline of a timed-out flow
local ip2mac  = {}          -- [normalised IP] = MAC
local mac_ips = {}          -- [MAC] = { v4, v6 }
local g_hist  = {}          -- whole-LAN rate window
local total_up, total_down = 0, 0
local rate_up, rate_down = 0, 0
local today = ldate("%Y-%m-%d")
local ev_offset = 0
local mac_at, ev_check_at, last_summary = 0, 0, 0
-- 分段计时开关：/tmp/oaf-flow/prof 存在才生效，平时每条分支都不进。
local prof = false
local ct_lines = 0
local last_full, cap_at, watched_until = 0, 0, 0
local skipped = 0

---------------------------------------------------------------- MAC table

local function bind(ip, mac)
	if not ip or not mac or ip == "0.0.0.0" or ip == "::" then return end
	if ip:lower():find("^fe80") then return end
	mac = mac:upper()
	ip2mac[n6(ip)] = mac
	local m = mac_ips[mac] or {}
	if ip:find(":") then m.v6 = ip else m.v4 = ip end
	mac_ips[mac] = m
end

local function refresh_macs()
	ip2mac, mac_ips = {}, {}

	-- official OAF table: Id / MAC / IPv4 / IPv6 / ...
	local f = io.open(AF, "r")
	if f then
		for line in f:lines() do
			local mac, v4, v6 = line:match(
				"^%s*%d+%s+(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s+(%S+)%s+(%S+)")
			if mac then bind(v4, mac); bind(v6, mac) end
		end
		f:close()
	end

	-- ARP: LAN hosts oafd has not (yet) put into af_client
	f = io.open(ARP, "r")
	if f then
		for line in f:lines() do
			local ip, mac = line:match(
				"^(%d+%.%d+%.%d+%.%d+)%s+%S+%s+%S+%s+(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
			if ip and mac then bind(ip, mac) end
		end
		f:close()
	end

	-- IPv6 neighbours (one fork every MAC_TTL seconds, not every sample)
	f = io.popen("ip -6 neigh show 2>/dev/null", "r")
	if f then
		for line in f:lines() do
			local ip, mac = line:match("^(%S+)%s+dev%s+%S+%s+lladdr%s+(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
			if ip and mac then bind(ip, mac) end
		end
		f:close()
	end

	for mac, m in pairs(mac_ips) do
		local c = clients[mac] or new_client(mac)
		clients[mac] = c
		c.ip = m.v4 or c.ip
		c.ip6 = m.v6 or c.ip6
		if c.ip6 ~= "" then c.ip6_list = { c.ip6 } end
	end
end

---------------------------------------------------------------- DESTROY event feed

local function event_alive()
	local f = io.open(EVPID, "r")
	if not f then return false end
	local pid = tonumber(f:read("*l") or "")
	f:close()
	if not pid or pid < 2 then return false end
	local h = io.open("/proc/" .. pid .. "/cmdline", "rb")
	if not h then return false end
	local cmd = h:read("*a") or ""
	h:close()
	return cmd:find("conntrack", 1, true) ~= nil
end

local function ensure_events(now)
	if now - ev_check_at < 20 and event_alive() then return end
	ev_check_at = now
	if event_alive() then return end
	os.execute("conntrack -E -e DESTROY -o timestamp </dev/null >> " .. EV ..
		" 2>/dev/null & echo $! > " .. EVPID)
	log("DESTROY event feed (re)started")
end

-- 重置 append 文件只能先杀掉写进程：`conntrack` 用的是自己的写偏移，底下把
-- 文件截成 0 字节后它仍在原偏移继续写，结果是一个前面全是 NUL 的稀疏文件，
-- 每行都被撑成几 MB。所以 reset 一律走 kill -> truncate -> 重新拉起。
local function feed_reset()
	local f = io.open(EVPID, "r")
	local pid = f and tonumber(f:read("*l") or "")
	if f then f:close() end
	if pid and pid > 1 and event_alive() then
		os.execute("kill " .. pid .. " 2>/dev/null")
	end
	local w = io.open(EV, "w")
	if w then w:close() end
	local p = io.open(EVPID, "w")
	if p then p:close() end
	ev_offset = 0
	ev_check_at = 0                        -- force the next check to restart
end

---------------------------------------------------------------- parsing

-- Returns {key, up, down, mac, appid, fam} or nil. The two tuples printed by
-- conntrack are (original, reply); for a LAN-originated flow the original
-- bytes are upstream and the reply bytes are downstream.
-- 一行 conntrack 长这样（两段 tuple，后一段是回程）：
--   ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.100 dst=1.2.3.4 sport=1234
--     dport=443 packets=10 bytes=5000 src=1.2.3.4 dst=192.168.1.100 ...
--
-- 一次带捕获的整行 match 拿齐所需字段（两段 tuple 的 bytes、首段 src/dst/端口），
-- 比"多次 find 定位 + 再 match 取值"省很多：同一台设备、同一份 /proc，719 行从
-- ~80 ms 降到 ~31 ms。ICMP 没有 sport/dport，用 type/code/id 的变体兜底。
local P46  = "src=(%S+)%s+dst=(%S+)%s+sport=(%d+)%s+dport=(%d+).-bytes=(%d+).-bytes=(%d+)"
local P46I = "src=(%S+)%s+dst=(%S+)%s+type=(%d+)%s+code=(%d+)%s+id=(%d+).-bytes=(%d+).-bytes=(%d+)"

local rec = { key = "", up = 0, down = 0, mac = "", appid = 0, fam = "ipv4" }

local function parse_line(line)
	local src, dst, p1, p2, v1, v2 = line:match(P46)
	local tag = ""
	if not src then
		local id
		src, dst, p1, p2, id, v1, v2 = line:match(P46I)
		if not src then skipped = skipped + 1; return nil end
		tag = "|" .. id
	end
	local b1, b2 = tonumber(v1), tonumber(v2)
	if not b1 or not b2 then skipped = skipped + 1; return nil end

	local is6 = src:find(":", 1, true) ~= nil
	local mac = ip2mac[is6 and n6(src) or src]
	local up, down
	if mac then
		up, down = b1, b2
	else
		-- WAN 发起（家里没人主动连）：回程在第二段。只有这条冷路径才多付
		-- 一次 plain find，第二次出现的 src= 就是回程的源地址。
		local f1 = line:find("src=", 1, true)
		local f2 = f1 and line:find("src=", f1 + 4, true)
		local src2 = f2 and line:match("(%S+)", f2 + 4)
		if src2 then
			is6 = src2:find(":", 1, true) ~= nil
			mac = ip2mac[is6 and n6(src2) or src2]
		end
		if not mac then skipped = skipped + 1; return nil end
		up, down = b2, b1
	end

	local appid = 0
	local ms = line:find("mark=", 1, true)
	if ms then
		appid = (tonumber(line:match("(%d+)", ms + 5)) or 0) % 65536
	end
	if appid > 32000 then appid = 0 end

	-- 4 元组本身唯一，proto 前缀是多余的；ICMP 要带上 id 才不串流。
	rec.key   = src .. "|" .. dst .. "|" .. p1 .. "|" .. p2 .. tag
	rec.up    = up
	rec.down  = down
	rec.mac   = mac
	rec.appid = appid
	rec.fam   = is6 and "ipv6" or "ipv4"
	return rec
end

---------------------------------------------------------------- accounting

local h_ts, h_bucket = -1, 1
local function hour_bucket(ts)
	if ts == h_ts then return h_bucket end
	h_ts, h_bucket = ts, (tonumber(ldate("%H", ts)) or 0) + 1
	return h_bucket
end

local function account(mac, du, dd, appid, fam, ts, tick)
	if du <= 0 and dd <= 0 then return end
	local c = clients[mac] or new_client(mac)
	clients[mac] = c
	local h = hour_bucket(ts)
	c.up = c.up + du
	c.down = c.down + dd
	c.hours[h].up = c.hours[h].up + du
	c.hours[h].down = c.hours[h].down + dd
	if fam == "ipv6" then c.up6 = c.up6 + du; c.down6 = c.down6 + dd end
	local a = c.apps[appid]
	if not a then
		a = { up = 0, down = 0, h = {}, a = {} }
		c.apps[appid] = a
	end
	a.up = a.up + du
	a.down = a.down + dd
	local hk = tostring(h - 1)
	if not a.h[hk] then a.h[hk] = { up = 0, down = 0 } end
	a.h[hk].up = a.h[hk].up + du
	a.h[hk].down = a.h[hk].down + dd
	-- Active time is settled ONCE per round in settle_round(). Adding `tick`
	-- here would add it once per flow, so a device with 12 open connections
	-- would report 12 seconds of usage for a single 1-second window.
	c.round_bytes = (c.round_bytes or 0) + du + dd
	c.round_apps[appid] = (c.round_apps[appid] or 0) + du + dd
	total_up = total_up + du
	total_down = total_down + dd
end

-- Decide "was this device / this app really in use during this window?".
-- A window counts only when it moved >= ACTIVE_MIN bytes; a keep-alive-only
-- long connection never reaches that and contributes zero seconds.
-- 把一轮「有流量」的活动并进该设备的访问段表。同一应用、间隔不超过
-- GAP_SEC 的相邻轮次算同一次访问，往后延尾即可；否则新开一段。
local function touch_seg(mac, id, from, to)
	local list = segs[mac]
	if not list then list = {}; segs[mac] = list end
	for i = #list, 1, -1 do
		local sg = list[i]
		if sg.id == id and sg.lt + GAP_SEC >= from then
			if to > sg.lt then sg.lt = to end
			if from < sg.ft then sg.ft = from end
			return
		end
	end
	list[#list + 1] = { id = id, ft = from, lt = to }
	if #list > SEG_MAX then table.remove(list, 1) end
end

local function settle_round(now, dt)
	local hk = tostring(tonumber(ldate("%H", now)))
	for _, c in pairs(clients) do
		if (c.round_bytes or 0) >= ACTIVE_MIN then
			c.active = c.active + dt
		end
		c.round_bytes = 0
		for id, bytes in pairs(c.round_apps or {}) do
			if bytes >= ACTIVE_MIN then
				local a = c.apps[id]
				if a then a.a[hk] = (a.a[hk] or 0) + dt end
				-- 同一个判定顺手记一段访问，访问记录直接用这份
				touch_seg(c.mac, id, now - dt, now)
			end
		end
		c.round_apps = {}
	end
end

-- Time-budgeted sliding average. A raw 1 s window is unusable (PPE writes
-- counters back every ~3.10 s, so 56.5% of 1 s samples are zero, CV 1.16).
-- Keep the newest samples covering at least 4 s: at 1 s sampling that is ~5
-- samples, error < 1%, and the number still changes every second.
local function rate(hist, du, dd, du6, dd6, dt)
	hist[#hist + 1] = { u = du, d = dd, u6 = du6, d6 = dd6, dt = dt }
	while #hist > 1 do
		local older = 0
		for i = 2, #hist do older = older + hist[i].dt end
		if older >= 4 then table.remove(hist, 1) else break end
	end
	local su, sd, su6, sd6, st = 0, 0, 0, 0, 0
	for _, x in ipairs(hist) do
		su = su + x.u; sd = sd + x.d
		su6 = su6 + x.u6; sd6 = sd6 + x.d6; st = st + x.dt
	end
	if st <= 0 then return 0, 0, 0, 0 end
	return su / st, sd / st, su6 / st, sd6 / st
end

---------------------------------------------------------------- JSON output

local function buckets_json(b)
	local out = {}
	for i = 1, 24 do
		out[i] = string.format('{"up":%s,"down":%s}', num(b[i].up), num(b[i].down))
	end
	return "[" .. table.concat(out, ",") .. "]"
end

-- Day archive for the 30-day chart and the visit-record byte gate.
-- `apps` used to be missing, which made every historical visit record fail
-- the 2 KiB gate and left the visit list / APP charts empty.
local function write_day()
	local drows, arows = {}, {}
	for mac, c in pairs(clients) do
		drows[#drows + 1] = '{"mac":' .. jstr(mac)
			.. ',"day_up":' .. num(c.up) .. ',"day_down":' .. num(c.down)
			.. ',"hours":' .. buckets_json(c.hours) .. "}"
		local items = {}
		for id, a in pairs(c.apps) do
			items[#items + 1] = '{"id":' .. num(id) .. ',"up":' .. num(a.up)
				.. ',"down":' .. num(a.down) .. "}"
		end
		arows[#arows + 1] = jstr(mac:lower()) .. ":[" .. table.concat(items, ",") .. "]"
	end
	atomic(DAYDIR .. "/" .. today .. ".json", '{"date":' .. jstr(today)
		.. ',"clients":[' .. table.concat(drows, ",") .. "]"
		.. ',"apps":{' .. table.concat(arows, ",") .. "}}")
end

local function write_outputs(now, full)
	local rows = {}
	for mac, c in pairs(clients) do
		rows[#rows + 1] = table.concat({
			'{"mac":' .. jstr(mac),
			'"ip":' .. jstr(c.ip),
			'"rate_up":' .. num(c.rate_up),
			'"rate_down":' .. num(c.rate_down),
			'"day_up":' .. num(c.up),
			'"day_down":' .. num(c.down),
			'"day_active":' .. num(c.active),
			'"day_online":' .. num(c.online),
			'"flows6":' .. num(c.flows6),
			'"ip6":' .. jstr(c.ip6),
			'"ip6_list":' .. (c.ip6 ~= "" and ("[" .. jstr(c.ip6) .. "]") or "[]"),
			'"rate_up6":' .. num(c.rate_up6),
			'"rate_down6":' .. num(c.rate_down6),
			'"day_up6":' .. num(c.up6),
			'"day_down6":' .. num(c.down6),
			'"flows":' .. num(c.flows) .. "}",
		}, ",")
	end
	atomic(STATSF, table.concat({
		'{"updated":' .. num(now),
		'"total_up":' .. num(total_up),
		'"total_down":' .. num(total_down),
		'"rate_up":' .. num(rate_up),
		'"rate_down":' .. num(rate_down),
		'"clients":[' .. table.concat(rows, ",") .. "]}",
	}, ","))

	-- The read layer caches hourly for 5 s and apps for 2 s; with 1 s rounds
	-- there is no point in re-serialising 24 x N buckets every second.
	-- stats.json above follows every round (rates + today), the rest is
	-- throttled by FULL_SEC in main().
	if not full then return end

	local gh = new_buckets()
	local hrows = {}
	for mac, c in pairs(clients) do
		for i = 1, 24 do
			gh[i].up = gh[i].up + c.hours[i].up
			gh[i].down = gh[i].down + c.hours[i].down
		end
		hrows[#hrows + 1] = '{"mac":' .. jstr(mac) .. ',"hours":'
			.. buckets_json(c.hours) .. "}"
	end
	atomic(HOURLYF, '{"updated":' .. num(now) .. ',"hours":'
		.. buckets_json(gh) .. ',"clients":[' .. table.concat(hrows, ",") .. "]}")

	local arows = {}
	for mac, c in pairs(clients) do
		local items = {}
		for id, a in pairs(c.apps) do
			local hs, as = {}, {}
			for k, v in pairs(a.h) do
				hs[#hs + 1] = jstr(k) .. ':{"up":' .. num(v.up)
					.. ',"down":' .. num(v.down) .. "}"
			end
			for k, v in pairs(a.a) do
				as[#as + 1] = jstr(k) .. ":" .. num(v)
			end
			items[#items + 1] = '{"id":' .. num(id)
				.. ',"up":' .. num(a.up) .. ',"down":' .. num(a.down)
				.. ',"h":{' .. table.concat(hs, ",") .. "}"
				.. ',"a":{' .. table.concat(as, ",") .. "}}"
		end
		arows[#arows + 1] = jstr(mac:lower()) .. ":[" .. table.concat(items, ",") .. "]"
	end
	atomic(APPSF, '{"updated":' .. num(now) .. ',"clients":{'
		.. table.concat(arows, ",") .. "}}")

	-- 访问段：秒级 [ft, lt]，只落最近 SEG_KEEP。写的同时把过期段真正删掉，
	-- 否则 segs 会随着天数一直长（tmpfs 也扛不住一个月）。
	local srows, scut = {}, now - SEG_KEEP
	for mac, list in pairs(segs) do
		local keep, items = {}, {}
		for i = 1, #list do
			local sg = list[i]
			if sg.lt >= scut then
				keep[#keep + 1] = sg
				items[#items + 1] = '{"id":' .. num(sg.id) .. ',"ft":'
					.. num(sg.ft) .. ',"lt":' .. num(sg.lt) .. "}"
			end
		end
		segs[mac] = keep
		if #items > 0 then
			srows[#srows + 1] = jstr(mac:lower()) .. ":[" .. table.concat(items, ",") .. "]"
		end
	end
	atomic(ACTIVEF, '{"updated":' .. num(now) .. ',"clients":{'
		.. table.concat(srows, ",") .. "}}")

	write_day()
end

-- No restore: all state is tmpfs and "restart clears" is the requested
-- behaviour. A service restart therefore starts a fresh, self-consistent
-- baseline (bytes before the sampler started cannot be reconstructed under
-- PPE offload anyway).
local function roll_day(newday)
	write_outputs(os.time(), true)
	log("day rollover %s -> %s", today, newday)
	today = newday
	clients, flows, retired, g_hist = {}, {}, {}, {}
	total_up, total_down, rate_up, rate_down = 0, 0, 0, 0
	refresh_macs()
end

-- Hard 10 MiB ceiling for the whole data directory. One fork per minute,
-- never per sample. Oldest day archives go first, then the two logs.
local function enforce_cap(now)
	if now - cap_at < CAP_CHECK then return end
	cap_at = now
	os.execute("ls -1 " .. DAYDIR .. "/*.json 2>/dev/null | sort | tail -n +"
		.. (KEEP_DAYS + 1) .. " | xargs -r rm -f")
	local p = io.popen("du -sk " .. DIR .. " 2>/dev/null", "r")
	local line = (p and p:read("*l")) or ""
	if p then p:close() end
	local kb = tonumber(line:match("^(%d+)")) or 0
	if kb <= CAP_KB then return end
	os.execute("for f in $(ls -1 " .. DAYDIR .. "/*.json 2>/dev/null | sort); do "
		.. "rm -f \"$f\"; "
		.. "[ $(du -sk " .. DIR .. " 2>/dev/null | awk '{print $1}') -le "
		.. CAP_KB .. " ] && break; done; : > " .. LOG)
	feed_reset()                            -- kill the writer before truncating
	log("data cap exceeded (%d KB), pruned oldest archives and logs", kb)
end

---------------------------------------------------------------- sample rounds

-- 轮次印章：用"这一轮见过它没有"代替 seen 表。原来每轮要新建一张
-- 1600 项的哈希表并逐条写入，现在只在 flow 记录上盖个数字。
local round_id = 0

local function snapshot(now, tick)
	round_id = round_id + 1
	local rid = round_id
	local per_mac, per_mac6 = {}, {}
	local ln = 0
	for line in io.lines(CT) do
		ln = ln + 1
		local f = parse_line(line)
		if f then
			per_mac[f.mac] = (per_mac[f.mac] or 0) + 1
			-- IPv6 rows are counted explicitly: n6() already normalised the
			-- expanded conntrack address against the neighbour table.
			if f.fam == "ipv6" then
				per_mac6[f.mac] = (per_mac6[f.mac] or 0) + 1
			end
			local st = flows[f.key]
			if not st then
				retired[f.key] = nil
				flows[f.key] = {
					last_up = f.up, last_down = f.down,
					mac = f.mac, appid = f.appid, fam = f.fam,
					gone = 0, r = rid,
				}
			else
				local du, dd = f.up - st.last_up, f.down - st.last_down
				if du < 0 then du = 0 end
				if dd < 0 then dd = 0 end
				if du > 0 or dd > 0 then
					account(st.mac, du, dd, st.appid, st.fam, now, tick)
				end
				st.last_up, st.last_down = f.up, f.down
				if f.appid ~= 0 then st.appid = f.appid end
				st.gone = 0
				st.r = rid
			end
		end
	end
	ct_lines = ln
	for mac, c in pairs(clients) do
		c.flows = per_mac[mac] or 0
		c.flows6 = per_mac6[mac] or 0
		local m = mac_ips[mac]
		if c.flows > 0 or m then c.online = c.online + tick end
	end
	for k, st in pairs(flows) do
		if st.r ~= rid then
			if st.gone == 0 then st.gone = now end
			if now - st.gone > GONE_TTL then
				retired[k] = { up = st.last_up, down = st.last_down, at = now }
				flows[k] = nil
			end
		end
	end
	for k, r in pairs(retired) do
		if now - r.at > 600 then retired[k] = nil end
	end
end

local function process_events(now, tick)
	local f = io.open(EV, "r")
	if not f then return 0 end
	local size = f:seek("end")
	if ev_offset > size then ev_offset = 0 end
	f:seek("set", ev_offset)
	local n = 0
	for line in f:lines() do
		local ts = tonumber(line:match("^%[(%d+%.?%d*)%]") or "") or now
		if line:find("%[DESTROY%]") then
			local rec = parse_line(line)
			if rec then
				local st, r = flows[rec.key], retired[rec.key]
				local du, dd, appid, fam
				if st then
					du, dd = rec.up - st.last_up, rec.down - st.last_down
					appid, fam = st.appid, st.fam
					flows[rec.key] = nil
				elseif r then
					-- Flow aged out of the table before its DESTROY arrived.
					-- Only the tail after the retired baseline is new.
					du, dd = rec.up - r.up, rec.down - r.down
					appid, fam = rec.appid, rec.fam
					retired[rec.key] = nil
				else
					-- Born and died between two snapshots: the event carries
					-- the whole flow. This is why snapshot-only accounting
					-- loses ~1.5% and the event feed is required.
					du, dd = rec.up, rec.down
					appid, fam = rec.appid, rec.fam
				end
				if du < 0 then du = 0 end
				if dd < 0 then dd = 0 end
				if du > 0 or dd > 0 then
					account(rec.mac, du, dd, appid, fam, ts, tick)
				end
				n = n + 1
			end
		end
	end
	ev_offset = f:seek("cur")
	f:close()
	if size > 1048576 then                   -- keep the log bounded (1 MiB tmpfs)
		feed_reset()
	end
	return n
end

-- luci.oaf_traffic writes "1" into WATCH on every page request. Consume it,
-- but keep a 3 s grace: at 1 Hz the CGI and the sampler can race by a few
-- hundred ms, and one missed marker would otherwise drop back to 20 s.
local function watched_now(now)
	local f = io.open(WATCH, "r")
	if f then
		local s = f:read("*a") or ""
		f:close()
		if s:find("1") then
			watched_until = now + 3
			local w = io.open(WATCH, "w")
			if w then w:close() end
		end
	end
	return now < watched_until
end

---------------------------------------------------------------- single instance

local function self_pid()
	local f = io.open("/proc/self/stat", "r")
	if not f then return 0 end
	local s = f:read("*a") or ""
	f:close()
	return tonumber(s:match("^(%d+)")) or 0
end

-- Two writers would each keep their own baselines and take turns overwriting
-- stats.json. Refuse to be the second one (procd respawn is harmless here).
local function single_instance()
	local f = io.open(LOCK, "r")
	if f then
		local pid = tonumber(f:read("*l") or "")
		f:close()
		if pid and pid > 1 and pid ~= self_pid() then
			local h = io.open("/proc/" .. pid .. "/cmdline", "rb")
			if h then
				local cmd = h:read("*a") or ""
				h:close()
				if cmd:find("oaf_ctstat", 1, true) then
					log("instance %d already running, exiting", pid)
					os.exit(0)
				end
			end
		end
	end
	local w = io.open(LOCK, "w")
	if w then w:write(tostring(self_pid())); w:close() end
end

---------------------------------------------------------------- main

local function count(t)
	local n = 0
	for _ in pairs(t) do n = n + 1 end
	return n
end

-- Sleep the leftover of a round, but never sleep through a page visit.
-- IDLE_SEC is 20 s; a plain nap() means the first visitor stares at frozen
-- rates for up to 20 s before the sampler notices. Wake every second instead
-- and break out early as soon as the read layer bumps the marker file, so the
-- switch to 1 Hz costs at most ~1 s. Sleeping is a nanosleep either way, the
-- only extra work on the idle path is reading a 1-byte file.
local function wait_round(want, early)
	local deadline = wall() + want
	while true do
		local left = deadline - wall()
		if left <= 0 then return end
		if early and left > 1.2 then
			if watched_now(os.time()) then return end
			nap(1)
		else
			nap(left)
		end
	end
end

local function main()
	os.execute("mkdir -p " .. DIR .. " " .. DAYDIR)
	single_instance()
	if io.open(DIR .. "/prof", "r") then
		prof = true
		os.remove(DIR .. "/prof")            -- one-shot: next restart is silent
	end
	feed_reset()
	refresh_macs()
	mac_at = os.time()
	ensure_events(os.time())
	log("oaf-ctstat start (tmpfs/UTC+8), %d MACs, idle=%ds active=%ds cap=%dKB",
		count(mac_ips), IDLE_SEC, ACTIVE_SEC, CAP_KB)

	local prevf = wall()
	local round, warmup = 0, 2
	while true do
		round = round + 1
		local t0 = wall()
		local now = os.time()
		local dt = t0 - prevf
		if dt < 0.05 then dt = 0.05 end
		prevf = t0

		local d = ldate("%Y-%m-%d")
		if d ~= today then roll_day(d) end
		if now - mac_at >= MAC_TTL then refresh_macs(); mac_at = now end
		ensure_events(now)

		local bu, bd = total_up, total_down
		local p0 = prof and wall() or 0
		snapshot(now, dt)
		local p1 = prof and wall() or 0
		local evn = process_events(now, dt)
		local p2 = prof and wall() or 0
		settle_round(now, dt)
		local p3 = prof and wall() or 0
		-- The very first rounds have no meaningful time base (dt is clamped to
		-- 1 s), so publish 0 B/s instead of a one-second spike.
		if warmup > 0 then
			warmup = warmup - 1
			rate_up, rate_down = 0, 0
		else
			rate_up, rate_down = rate(g_hist,
				total_up - bu, total_down - bd, 0, 0, dt)
		end

		for _, c in pairs(clients) do
			if warmup == 0 then
				c.rate_up, c.rate_down, c.rate_up6, c.rate_down6 = rate(c.hist,
					c.up - c.prev_up, c.down - c.prev_down,
					c.up6 - c.prev_up6, c.down6 - c.prev_down6, dt)
			end
			c.prev_up, c.prev_down = c.up, c.down
			c.prev_up6, c.prev_down6 = c.up6, c.down6
		end

		local full = (round == 1) or (now - last_full >= FULL_SEC)
		if full then last_full = now end
		write_outputs(now, full)
		local p4 = prof and wall() or 0
		enforce_cap(now)

		if prof then
			log("prof snap=%.1f ev=%.1f settle=%.1f write=%.1f ms lines=%d",
				(p1 - p0) * 1000, (p2 - p1) * 1000, (p3 - p2) * 1000,
				(p4 - p3) * 1000, ct_lines)
		end

		if now - last_summary >= 300 then
			last_summary = now
			log("up=%s down=%s rate=%s/%s B/s clients=%d flows=%d events=%d skipped=%d",
				num(total_up), num(total_down), num(rate_up), num(rate_down),
				count(clients), count(flows), evn, skipped)
			skipped = 0
		end

		local interval, early = watched_now(now) and ACTIVE_SEC or IDLE_SEC, true
		-- 表越大一轮全表扫描越贵。超过阈值就把节奏放到 2 s：前端本来就是
		-- 1 Hz 取一次，2 s 窗口只是让速率更平滑，观感没有损失，CPU 却减半。
		if interval < THROTTLE_SEC and ct_lines > THROTTLE_LINES then
			interval, early = THROTTLE_SEC, false
		end
		wait_round(interval - (wall() - t0), early)
	end
end

main()
