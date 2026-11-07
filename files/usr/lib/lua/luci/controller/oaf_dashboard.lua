module("luci.controller.oaf_dashboard", package.seeall)
-- every traffic number on this page comes from oaf-flowd when it is available;
-- fwx only keeps the parts that need app classification (active app, URL)
local traf = require "luci.oaf_traffic"

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
