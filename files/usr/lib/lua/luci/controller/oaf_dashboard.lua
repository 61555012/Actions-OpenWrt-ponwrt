module("luci.controller.oaf_dashboard", package.seeall)
-- every traffic number on this page comes from oaf-flowd when it is available;
-- fwx only keeps the parts that need app classification (active app, URL)
local traf = require "luci.oaf_traffic"

-- "正在访问" 卡片。fwx 的 active_app.list 是"最近一次识别出来的那条流"：
-- DPI 每命中一条新流才追加一条，网络安静下来它就停在 1~2 条，看起来像坏了。
-- 这里补两路数据，按应用 id 去重，最多 10 个：
--   1) 在线设备的当前应用（fwx 直接给的 app / app_id）
--   2) 在线设备最近用过的应用（applist，fwx 自己按使用情况排好序）
-- 前两条流条目信息最全（域名/端口/协议），保持原样不动。
local ACTIVE_APP_MAX = 10
local ACTIVE_HOST_MAX = 8       -- dashboard.htm 自己会 slice(0, 8)
local HOST_MAX_AGE = 6 * 3600   -- 内核 SNI 表会留很久以前的条目，只补 6 小时内的
local CACHE_TTL = 5             -- 仪表盘 3 秒刷一次，设备表 5 秒拉一次就够
local users_cache, users_at = nil, 0

-- 应用补齐和 URL 补设备名都要用 fwx 的设备表，统一在这一层做 5 秒缓存
local function all_users(utl)
	local now = os.time()
	if users_cache and (now - users_at) < CACHE_TTL then
		return users_cache
	end
	local resp = utl.ubus("fwx", "common", {
		api = "get_all_users",
		data = { flag = 3, page = 1, page_size = 200 }
	})
	local users = resp and resp.code == 2000 and resp.data and resp.data.list
	if type(users) == "table" then
		users_cache, users_at = users, now
		return users
	end
	return users_cache or {}
end

-- 从设备表里抽出"现在在用 / 最近在用"的应用，按应用 id 去重
local function device_apps(users, now)
	local out, seen = {}, {}
	local function push(id, name, u)
		if #out >= ACTIVE_APP_MAX or not name or name == "" or seen[id] then
			return
		end
		seen[id] = true
		out[#out + 1] = {
			id = id,
			name = name,
			mac = u.mac or "",
			hostname = u.hostname or u.nickname or "",
			src_ip = (u.ip and u.ip ~= "" and u.ip ~= "0.0.0.0") and u.ip or (u.ipv6 or u.ip6 or ""),
			timestamp = now
		}
	end
	-- 在线设备各自正在用的应用优先
	for _, u in ipairs(users) do
		if tonumber(u.online) == 1 then
			local id = tonumber(u.app_id) or 0
			if id > 0 then
				push(id, u.app, u)
			end
		end
	end
	-- 不够再用这些设备最近用过的应用补齐
	for _, u in ipairs(users) do
		if tonumber(u.online) == 1 then
			for _, app in ipairs(u.applist or {}) do
				local id = tonumber(app.id) or 0
				if id > 0 then
					push(id, app.name, u)
				end
			end
		end
	end
	return out
end

local function fill_active_apps(utl, active_app)
	if type(active_app) ~= "table" then
		return
	end
	local list = active_app.list
	if type(list) ~= "table" then
		list = {}
		active_app.list = list
	end
	local extra_cache = device_apps(all_users(utl), os.time())
	for _, a in ipairs(extra_cache) do
		if #list >= ACTIVE_APP_MAX then
			break
		end
		local dup = false
		for _, b in ipairs(list) do
			if tonumber(a.id) == tonumber(b.id) then
				dup = true
				break
			end
		end
		if not dup then
			list[#list + 1] = a
		end
	end
end

-- "活跃 URL" 卡片。fwx 的 active_host.list 只留一个很短的时间窗里新抓到的
-- Host：实测 one.one.one.one 刚出现时返回 total=1，同一批抖音域名 40 分钟后
-- 就被过滤成 total=0 / list=[]，get_all_users 里每个设备的 url 也全是空串。
-- 但内核的 /proc/net/af_active_host 还留着这些 SNI（DPI 一直工作正常）。
-- 开了硬件加速之后大量流量走长连接 / QUIC，新 SNI 出得非常慢，卡片就长期空白。
-- 这里把内核表里 6 小时内的条目补进来，fwx 自己的新条目保持优先。
local function bare_host(h)
	local s = tostring(h.host or h.url or "")
	s = s:gsub("^https?://", ""):gsub("^www%.", ""):gsub("[:/].*$", "")
	return s:lower()
end

local function kernel_active_hosts(utl)
	local f = io.open("/proc/net/af_active_host", "r")
	if not f then
		return {}
	end
	local names = {}
	for _, u in ipairs(all_users(utl)) do
		if u.mac and u.mac ~= "" then
			names[u.mac:lower()] = (u.nickname and u.nickname ~= "" and u.nickname)
				or u.hostname or ""
		end
	end
	local now = os.time()
	local out, seen = {}, {}
	for line in f:lines() do
		-- Host MAC SrcIP SrcPort DstIP DstPort Proto AppProto Drop LastUpdate
		local host, mac, _, _, _, dport, _, app_proto, _, last = line:match(
			"^(%S+)%s+(%S+)%s+(%S+)%s+(%d+)%s+(%S+)%s+(%d+)%s+(%S+)%s+(%d+)%s+(%d+)%s+(%d+)")
		local ts = tonumber(last)
		local age = ts and (now - ts)
		if host and mac and age and age >= -300 and age < HOST_MAX_AGE then
			local key = mac:lower() .. "|" .. host:lower()
			if not seen[key] then
				seen[key] = true
				local port = tonumber(dport) or 0
				local ap = tonumber(app_proto) or 0
				local scheme = (ap == 1 or port == 80) and "http" or "https"
				local name = names[mac:lower()] or ""
				out[#out + 1] = {
					mac = mac:lower(),
					name = name,
					hostname = name,
					host = host,
					url = scheme .. "://" .. host,
					app_proto = ap,
					dst_port = port,
					timestamp = ts
				}
			end
		end
	end
	f:close()
	table.sort(out, function(a, b) return a.timestamp > b.timestamp end)
	while #out > ACTIVE_HOST_MAX do
		table.remove(out)
	end
	return out
end

local function fill_active_hosts(utl, active_host)
	if type(active_host) ~= "table" then
		active_host = {}
	end
	local list = active_host.list
	if type(list) ~= "table" then
		list = {}
	end
	local seen = {}
	for _, h in ipairs(list) do
		seen[tostring(h.mac or ""):lower() .. "|" .. bare_host(h)] = true
	end
	for _, h in ipairs(kernel_active_hosts(utl)) do
		if #list >= ACTIVE_HOST_MAX then
			break
		end
		local key = h.mac .. "|" .. bare_host(h)
		if not seen[key] then
			seen[key] = true
			list[#list + 1] = h
		end
	end
	active_host.list = list
	active_host.total = #list
	return active_host
end

function index()
	entry({"admin", "services", "oaf", "dashboard"}, cbi("oaf/dashboard", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}),
	 _("Dashboard"), 10).leaf = true
	
	entry({"admin", "services", "oaf", "api", "dashboard", "get_dashboard_common"}, call("get_dashboard_common")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "get_init_status"}, call("get_init_status")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "set_init_status"}, call("set_init_status")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "set_notice_status"}, call("set_notice_status")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "get_daily_top_users"}, call("get_daily_top_users")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "get_history_traffic_stats"}, call("get_history_traffic_stats")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "get_global_traffic_stats"}, call("get_global_traffic_stats")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "get_active_users"}, call("get_active_users")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "get_app_type_stats"}, call("get_app_type_stats")).leaf = true
end

function get_dashboard_common()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_dashboard_common"
	req_obj.CopyRight = "www.fanchmwrt.com"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	local data = {
		system_status = {},
		network_status = {},
		active_app = {total = 0, list = {}},
		advanced = {disable_hnat = 0, notice_status = 0},
		interface_traffic = {interface = "wan", traffic = {}}
	}
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		data = resp_obj.data
	end

	fill_active_apps(utl, data.active_app)
	data.active_host = fill_active_hosts(utl, data.active_host)

	-- "today's traffic" on the card. The field is in KB and fwx only moves it
	-- when a flow closes, so during a big transfer it stands still; offload
	-- makes that window as long as the flow itself. oaf-flowd keeps the running
	-- total, converted to the same unit the page already expects.
	local total = traf.totals()
	if total then
		data.system_status = data.system_status or {}
		data.system_status.flow = {
			today_up = math.floor(total.up / 1024),
			today_down = math.floor(total.down / 1024)
		}
		data.traffic_source = "oaf-flowd"
		if traf.accel() then
			data.accel = 1
		end
	end

	luci.http.write_json(data)
end

function get_global_traffic_stats()
	local utl = require "luci.util"

	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "get_global_traffic_stats"
	req_obj.data = {}

	-- date=0 used to be forwarded as-is, and fwx answers 4000 for it, which
	-- left the chart empty on a plain refresh. 0/absent now means today.
	local date = tonumber(luci.http.formvalue("date")) or 0
	if date > 0 then
		req_obj.data.date = date
	end

	local resp_obj = utl.ubus("fwx", "common", req_obj)

	local data = { date = 0, is_today = 1, hourly_traffic = {} }
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		data = resp_obj.data
	end

	-- today's 24 buckets, from the sampler instead of the hook: with
	-- offloading on, fwx moves an hour's bytes only after the flow closes
	local _, hours = traf.hours()
	if hours and (date == 0 or date == (tonumber(data.date) or 0)) then
		local rows = {}
		for i = 1, 24 do
			local slot = hours[i] or {}
			rows[i] = {
				hour = i - 1,
				traffic = { up_bytes = slot.up or 0, down_bytes = slot.down or 0 }
			}
		end
		data.hourly_traffic = rows
		data.is_today = 1
	end

	luci.http.write_json(data)
end

function get_history_traffic_stats()
	local utl = require "luci.util"

	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "get_history_traffic_stats"
	req_obj.data = {}

	local days = luci.http.formvalue("days")
	if days then
		req_obj.data.days = tonumber(days) or 30
	else
		req_obj.data.days = 30
	end

	-- oaf-flowd writes one file per finished day, so the 30-day bar chart can be
	-- rebuilt from those instead of from a counter that needs the flow to
	-- close before it moves. Falls through to fwx when there is no history.
	local files = traf.days(req_obj.data.days)
	if #files > 0 then
		local rows, total_up, total_down = {}, 0, 0
		for _, d in ipairs(files) do
			total_up = total_up + d.up
			total_down = total_down + d.down
			rows[#rows + 1] = {
				date_str = d.date,
				up_bytes = d.up,
				down_bytes = d.down,
				total_bytes = d.up + d.down
			}
		end
		luci.http.write_json({
			days = req_obj.data.days,
			total_up_bytes = total_up,
			total_down_bytes = total_down,
			total_bytes = total_up + total_down,
			list = rows
		})
		return
	end

	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			days = req_obj.data.days,
			total_up_bytes = 0,
			total_down_bytes = 0,
			total_bytes = 0,
			list = {}
		})
	end
end

function get_init_status()
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "get_init_status"
	req_obj.data = {}

	local resp_obj = utl.ubus("fwx", "common", req_obj)
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({init_status = 1})
	end
end

function set_init_status()
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "set_init_status"
	req_obj.data = { init_status = 1 }

	local resp_obj = utl.ubus("fwx", "common", req_obj)
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({init_status = 0})
	end
end

function set_notice_status()
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "set_dashboard_notice_status"
	req_obj.data = { notice_status = 1 }

	local resp_obj = utl.ubus("fwx", "common", req_obj)
	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json({code = 2000, notice_status = 1})
	else
		luci.http.write_json({code = 1})
	end
end

function get_daily_top_users()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_daily_top_users"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	local data = { date = 0, total_count = 0, users = {} }
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		data = resp_obj.data
	end

	-- Re-rank on oaf-flowd's numbers instead of trusting the order fwx produced.
	-- Under offload fwx books a flow only when it closes, so its ranking is
	-- whatever was true some minutes ago; a client that is downloading right
	-- now can be missing from its list entirely, which is why the list is
	-- topped up from oaf-flowd as well.
	local index = traf.index()
	if index then
		local seen, rows = {}, {}
		for _, u in ipairs(data.users or {}) do
			local c = index[(u.mac or ""):upper()]
			seen[(u.mac or ""):upper()] = true
			if c then
				u.up_bytes, u.down_bytes = c.today_up, c.today_down
				u.total_bytes = c.today_up + c.today_down
				if c.ip ~= "" and (u.ip == nil or u.ip == "" or u.ip == "0.0.0.0") then
					u.ip = c.ip
				end
				if c.name ~= "" and (u.hostname == nil or u.hostname == "") then
					u.hostname = c.name
				end
			end
			rows[#rows + 1] = u
		end
		for mac, c in pairs(index) do
			if not seen[mac] and c.today_up + c.today_down > 0 then
				rows[#rows + 1] = {
					mac = mac:lower(),
					ip = c.ip,
					hostname = c.name,
					nickname = "",
					up_bytes = c.today_up,
					down_bytes = c.today_down,
					total_bytes = c.today_up + c.today_down
				}
			end
		end
		table.sort(rows, function(a, b)
			return (a.total_bytes or 0) > (b.total_bytes or 0)
		end)
		while #rows > 8 do
			rows[#rows] = nil
		end
		data.users = rows
		data.total_count = #rows
	end

	luci.http.write_json(data)
end

function get_active_users()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_active_users"
	req_obj.data = {}
	
	local count = luci.http.formvalue("count")
	if count then
		req_obj.data.count = tonumber(count) or 8
	else
		req_obj.data.count = 8
	end
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)

	local data = { total_count = 0, users = {} }
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		data = resp_obj.data
	end

	local users = data.users or {}
	local n_fwx = #users
	traf.merge_list(users)

	-- A device that is pulling data right now can be missing from fwx's own
	-- idea of "active" when the flow was offloaded: the hook never saw it
	-- start. oaf-flowd knows it is busy, so it gets appended - the rows that fwx
	-- does return keep their app and URL, which is what this panel is for.
		local index = traf.index()
	if index then
		local seen = {}
		for _, u in ipairs(users) do
			seen[(u.mac or ""):upper()] = true
		end
		for mac, c in pairs(index) do
			if not seen[mac] and (c.rate_up + c.rate_down) > 4096 then
				users[#users + 1] = {
					mac = mac:lower(),
					ip = c.ip,
					hostname = c.name,
					nickname = "",
					up_rate = c.rate_up,
					down_rate = c.rate_down,
					rssi = 0,
					rx_rate = 0,
					tx_rate = 0,
					band = "",
					wifi_ifname = "",
					is_wireless = 0,
					terminal_type = "wired",
					today_up_bytes = c.today_up,
					today_down_bytes = c.today_down,
					app = "",
					url = ""
				}
			end
		end
		-- 按“此刻谁在跑”重排再截断：fwx 自己那 8 条在 offload 下可能
		-- 全是刚断流量的设备，把真正在下载的那台挡在门外。
		table.sort(users, function(a, b)
			local da, db = tonumber(a.down_rate) or 0, tonumber(b.down_rate) or 0
			if da ~= db then return da > db end
			local ua, ub = tonumber(a.up_rate) or 0, tonumber(b.up_rate) or 0
			if ua ~= ub then return ua > ub end
			return tostring(a.mac or "") < tostring(b.mac or "")
		end)
		local want = tonumber(req_obj.data.count) or 8
		while #users > want do
			users[#users] = nil
		end
		data.users = users
		data.total_count = #users
	end

	luci.http.write_json(data)
end

function get_app_type_stats()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local stat_type = luci.http.formvalue("type") or "hourly"
	
	local req_obj = {}
	req_obj.api = "get_global_app_type_stats"
	req_obj.data = {
		type = stat_type,
		limit = 10
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			type = stat_type,
			limit = 10,
			total_count = 0,
			types = {}
		})
	end
end
