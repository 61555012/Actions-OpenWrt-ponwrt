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
local VENDORS = "/tmp/oaf-flow/vendors.json"
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
				-- IPv6 side of the same device: the counters are an exact
				-- share of the totals above (a flow is entirely one family),
				-- and ip6 is the one address worth showing
				ip6        = c.ip6 or "",
				ip6_list   = c.ip6_list,
				rate_up6   = c.rate_up6 or 0,
				rate_down6 = c.rate_down6 or 0,
				today_up6   = (c.day_up6 or 0) + (c.live_up6 or 0),
				today_down6 = (c.day_down6 or 0) + (c.live_down6 or 0),
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
	local v = read_json(VENDORS)
	if v and type(v.macs) == "table" then
		vendors = v.macs
	else
		vendors = nil
	end
	return vendors
end

function M.vendor(mac)
	local m = M.vendors()
	if not m then
		return nil
	end
	return m[mac_key(mac)]
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
	u.today_up_bytes = c.today_up
	u.today_down_bytes = c.today_down
	-- 上网时长改由采样器提供：fwx 的那个数字不动，覆盖掉才不会一直显示
	-- 同一个值。采样器没有这台设备的记录时（刚重启）保持 fwx 的原值。
	if (c.day_active or 0) > 0 then
		u.today_active_time = c.day_active
	end
	u.up_rate6 = c.rate_up6
	u.down_rate6 = c.rate_down6
	u.today_up6_bytes = c.today_up6
	u.today_down6_bytes = c.today_down6
	if c.ip ~= "" and (u.ip == nil or u.ip == "" or u.ip == "0.0.0.0") then
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
