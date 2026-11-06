module("luci.controller.oaf_user", package.seeall)
local utl = require "luci.util"
-- traffic columns come from oaf-flowd when it is running: the fwx counters sit in
-- a netfilter hook, so hardware-offloaded flows never reach them
local traf = require "luci.oaf_traffic"

function index()
	local page
	entry({"admin", "services", "oaf", "users"}, alias("admin", "services", "oaf", "users", "list"), _("User List"), 20).dependent = true
	entry({"admin", "services", "oaf", "users", "list"}, cbi("oaf/user_list", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}),
	 nil).leaf = true
	
	entry({"admin", "services", "oaf", "users", "detail"}, cbi("oaf/user_detail", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "user_status"}, call("user_status"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "dev_visit_list"}, call("get_dev_visit_list"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "dev_visit_time"}, call("get_dev_visit_time"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "app_class_visit_time"}, call("get_app_class_visit_time"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_class_list"}, call("get_class_list"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_all_users"}, call("get_all_users"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_system_base_info"}, call("get_system_base_info"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_mac_blacklist"}, call("get_mac_blacklist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "add_mac_blacklist"}, call("add_mac_blacklist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "del_mac_blacklist"}, call("del_mac_blacklist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_parental_control_detail"}, call("get_parental_control_detail"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "set_nickname"}, call("set_nickname"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_hourly_stats"}, call("get_hourly_stats"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_user_basic_info"}, call("get_user_basic_info"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_online_offline_records"}, call("get_online_offline_records"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_user_parental_control_rules"}, call("get_user_parental_control_rules"), nil).leaf = true
end

function get_hostname_by_mac(dst_mac)
    local leasefile = "/tmp/dhcp.leases"
    local fd = io.open(leasefile, "r")
	if not fd then return end
    while true do
        local ln = fd:read("*l")
        if not ln then
            break
        end
        local ts, mac, ip, name, duid = ln:match("^(%d+) (%S+) (%S+) (%S+) (%S+)")
        if  dst_mac == mac then
            fd:close()
            return name
        end
    end
	fd:close()
    return ""
end


-- 应用名表在 fwx 的 class_list 里（每项 "id,name"）。上游是从
-- /tmp/appfilter/*.class 里 grep 出来的，那是旧版 OAF 的路径，这版固件
-- 根本没有这个目录：查一个名字就要 fork 一条 find，日志里刷满
-- "No such file or directory"，结果还永远是空。
local app_names

local function load_app_names()
	if app_names then
		return app_names
	end
	app_names = {}
	local resp = utl.ubus("fwx", "common", {
		api = "class_list",
		CopyRight = "www.fanchmwrt.com",
		data = {}
	})
	if resp and resp.code == 2000 and resp.data and type(resp.data.class_list) == "table" then
		for _, cls in ipairs(resp.data.class_list) do
			for _, item in ipairs(cls.app_list or {}) do
				local id, name = tostring(item):match("^(%d+),(.+)$")
				if id then
					app_names[id] = name
				end
			end
		end
	end
	return app_names
end

function get_app_name_by_id(appid)
	local name = load_app_names()[tostring(appid or "")]
	if name and name ~= "" then
		return name
	end
	if tonumber(appid) and tonumber(appid) > 0 then
		return "App" .. tostring(appid)
	end
	return ""
end

function cmp_func(a,b)
	return a.latest_time > b.latest_time
end

function normalize_mac(mac)
	if not mac then
		return ""
	end
	return tostring(mac):gsub("^%s+", ""):gsub("%s+$", ""):upper()
end

function call_fwx_common(api, data)
	local req_obj = {}
	req_obj.api = api
	req_obj.data = data or {}
	return utl.ubus("fwx", "common", req_obj)
end

function user_status()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local fd = io.open("/proc/net/af_client","r")
	status_buf=fd:read('*a')
	fd:close()
	user_array=json.parse(status_buf)
	
	local req_obj = {}
	req_obj.api = "visit_list"
	req_obj.data = {}
	local visit_obj = utl.ubus("fwx", "common", req_obj)
	
	local user_array = {}
	if visit_obj and visit_obj.code == 2000 and visit_obj.data and visit_obj.data.dev_list then
		user_array = visit_obj.data.dev_list
	end
	local history={}
	for i, v in pairs(user_array) do
		visit_array=user_array[i].visit_info
		for j,s in pairs(visit_array) do
			-- 上游这里有一行 print() 调试输出。CGI 下 stdout 就是响应体，
			-- 每台设备的每条访问记录都往 header 区写一行，接口直接坏掉
			-- （浏览器报 "got more than 100 headers"），已删除。
			total_time=visit_array[j].latest_time - visit_array[j].first_time;
			history[#history+1]={
				mac=user_array[i].mac,
				ip=user_array[i].ip,
				hostname=get_hostname_by_mac(user_array[i].mac),
				appid=visit_array[j].appid,
				appname=get_app_name_by_id(visit_array[j].appid),
				total_num=0,
				drop_num=0,
				latest_action=visit_array[j].latest_action,
				latest_time=os.date("%Y/%m/%d %H:%M:%S", visit_array[j].latest_time),
				first_time=os.date("%Y/%m/%d %H:%M:%S", visit_array[j].first_time),
				total_time=total_time
			}
		end
	end
	table.sort(history, cmp_func)
	luci.http.write_json(history);
end

function get_class_list()
	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.CopyRight = "www.fanchmwrt.com"
	req_obj.api = "class_list"
	req_obj.data = {}

	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({class_list = {}})
	end
end


-- 设备列表按今日上网流量降序。today_up_bytes / today_down_bytes 是 oaf-flowd
-- 合并进来的 v4+v6 全量，和页面「上网流量」列显示的是同一个数，所以排序结果
-- 与眼睛看到的数字一致。同流量时按 IP、再按 MAC 递增兜底：table.sort 不稳定，
-- 顺序一抖动前端列表指纹就变，1 秒一次的轮询会退化成每秒全量重绘。
local function traffic_bytes(u)
	return (tonumber(u.today_up_bytes) or 0) + (tonumber(u.today_down_bytes) or 0)
end

local function sort_by_traffic(list)
	if type(list) ~= "table" or #list < 2 then
		return list
	end
	table.sort(list, function(a, b)
		local ta, tb = traffic_bytes(a), traffic_bytes(b)
		if ta ~= tb then
			return ta > tb
		end
		local ia, ib = tostring(a.ip or ""), tostring(b.ip or "")
		if ia ~= ib then
			return ia < ib
		end
		return tostring(a.mac or "") < tostring(b.mac or "")
	end)
	return list
end

function get_all_users()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")

	local flag = luci.http.formvalue("flag")
	local page = tonumber(luci.http.formvalue("page")) or 1
	local page_size = tonumber(luci.http.formvalue("page_size")) or 15
	if page < 1 then page = 1 end
	if page_size < 1 then page_size = 15 end

	-- fwx 只会把“它返回的那一页”排好序，而这里要的是全表按今日流量
	-- 降序：照原样把 page/page_size 透传上去，第 2 页里流量比第 1 页
	-- 末位还大的设备就永远上不去。所以先分几次把整张表拉回来，
	-- 排序之后再切片。
	local first = utl.ubus("fwx", "common", {
		api = "get_all_users",
		data = { flag = flag, page = 1, page_size = 200 }
	})
	if not (first and first.code == 2000 and first.data) then
		luci.http.write_json({ data = first or {} })
		return
	end
	local data = first.data
	local list = data.list or {}
	local server_pages = tonumber(data.total_page) or 1
	local p, guard = 2, 0
	while p <= server_pages and p <= 20 do
		guard = guard + 1
		local more = utl.ubus("fwx", "common", {
			api = "get_all_users",
			data = { flag = flag, page = p, page_size = 200 }
		})
		if not (more and more.code == 2000 and more.data and more.data.list) then
			break
		end
		for _, u in ipairs(more.data.list) do
			list[#list + 1] = u
		end
		p = p + 1
	end

	traf.merge_list(list)
	sort_by_traffic(list)

	local total = #list
	local from = (page - 1) * page_size + 1
	local to = math.min(total, from + page_size - 1)
	local slice = {}
	for i = from, to do
		slice[#slice + 1] = list[i]
	end

	data.list = slice
	data.page = page
	data.page_size = page_size
	data.total_num = total
	data.total_page = math.max(1, math.ceil(total / page_size))
	luci.http.write_json({ data = data })
end

function get_system_base_info()
	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "get_system_base_info"
	req_obj.data = {}

	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			user_session_enable = 0
		})
	end
end

function get_mac_blacklist()
	luci.http.prepare_content("application/json")

	local resp_obj = call_fwx_common("get_mac_blacklist", {})
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json({code = 0, data = resp_obj.data, message = "success"})
	else
		luci.http.write_json({code = 1, data = {list = {}}, message = "failed"})
	end
end

function add_mac_blacklist()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")

	local mac_list = {}
	local mac = normalize_mac(luci.http.formvalue("mac"))
	if mac ~= "" then
		table.insert(mac_list, mac)
	else
		local data_str = luci.http.formvalue("data")
		if data_str and data_str ~= "" then
			local data = json.parse(data_str)
			if data and type(data.mac_list) == "table" then
				for _, item in ipairs(data.mac_list) do
					local normalized_mac = normalize_mac(item)
					if normalized_mac ~= "" then
						table.insert(mac_list, normalized_mac)
					end
				end
			end
		end
	end

	if #mac_list == 0 then
		luci.http.write_json({code = 1, message = "Invalid mac"})
		return
	end

	local resp_obj = call_fwx_common("add_mac_blacklist", {mac_list = mac_list})
	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json({code = 0, message = "success"})
	else
		luci.http.write_json({code = 1, message = "failed"})
	end
end

function del_mac_blacklist()
	luci.http.prepare_content("application/json")
	local mac = normalize_mac(luci.http.formvalue("mac"))
	if mac == "" then
		luci.http.write_json({code = 1, message = "Invalid mac"})
		return
	end

	local resp_obj = call_fwx_common("del_mac_blacklist", {mac = mac})
	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json({code = 0, message = "success"})
	else
		luci.http.write_json({code = 1, message = "failed"})
	end
end

function get_parental_control_detail()
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.api = "get_parental_control_detail"
	req_obj.data = {
		mac = luci.http.formvalue("mac")
	}

	local resp_obj = utl.ubus("fwx", "common", req_obj)
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			pc_status = "unlimited",
			pc_status_key = "unlimited",
			af_whitelist = 0,
			mf_whitelist = 0,
			appfilter_rules = {},
			macfilter_rules = {}
		})
	end
end

function get_user_parental_control_rules()
	luci.http.prepare_content("application/json")

	local target_mac = normalize_mac(luci.http.formvalue("mac"))
	if target_mac == "" then
		luci.http.write_json({
			mac = "",
			af_whitelist = 0,
			mf_whitelist = 0,
			list = {}
		})
		return
	end

	local req_obj = {
		api = "get_user_parental_control_rules",
		data = {
			mac = target_mac
		}
	}
	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 and type(resp_obj.data) == "table" then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			mac = target_mac,
			af_whitelist = 0,
			mf_whitelist = 0,
			list = {}
		})
	end
end

function get_oaf_status()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_oaf_status"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json(resp_obj or {})
	end
end


function set_nickname()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "set_nickname"
	req_obj.data = {
		mac = luci.http.formvalue("mac"),
		nickname = luci.http.formvalue("nickname")
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj);
	
	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json(resp_obj.data or {})
	else
		luci.http.write_json(resp_obj or {})
	end
end


function get_dev_visit_time(mac)
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "dev_visit_time"
	req_obj.data = {
		mac = mac
	}
	
	local visit_obj = utl.ubus("fwx", "common", req_obj)
	
	local visit_list = {}
	if visit_obj and visit_obj.code == 2000 and visit_obj.data and visit_obj.data.list then
		visit_list = visit_obj.data.list
	end
	luci.http.write_json(visit_list)
end

function get_app_class_visit_time(mac)
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "app_class_visit_time"
	req_obj.data = {
		mac = mac
	}
	
	local visit_obj = utl.ubus("fwx", "common", req_obj)
	
	local class_array = {}
	if visit_obj and visit_obj.code == 2000 and visit_obj.data and visit_obj.data.class_list then
		class_array = visit_obj.data.class_list
	end
	luci.http.write_json(class_array)
end


function get_dev_visit_list(mac)
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "dev_visit_list"
	req_obj.data = {
		mac = mac
	}
	
	local page = luci.http.formvalue("page")
	local page_size = luci.http.formvalue("page_size")
	if page then
		req_obj.data.page = tonumber(page) or 1
	end
	if page_size then
		req_obj.data.page_size = tonumber(page_size) or 15
	end
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json(resp_obj or {})
	end
end

function get_hourly_stats(mac)
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_hourly_top_apps"
	req_obj.data = {
		mac = mac
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	local data = {
		mac = mac,
		date = 0,
		is_today = 1,
		hourly_stats = {}
	}
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		data = resp_obj.data
	end

	-- The per-hour bars were the last thing still coming from the fwx
	-- counters, and under flow offload an hour only gets its bytes when the
	-- flow closes: the chart sat flat at zero during a 200 MB download and
	-- then jumped. oaf-flowd knows the buckets, so they replace the numbers while
	-- fwx keeps supplying what it is good at - app names and online time.
	local cw = traf.client_hours(mac)
	if cw then
		local rows = {}
		for i = 1, 24 do
			local slot = cw[i] or {}
			rows[i] = {
				hour = i - 1,
				apps = {},
				traffic = { up_bytes = slot.up or 0, down_bytes = slot.down or 0 },
				online_time = 0,
				active_time = 0
			}
		end
		for _, old in ipairs(data.hourly_stats or {}) do
			local i = (tonumber(old.hour) or 0) + 1
			if rows[i] then
				rows[i].apps = old.apps or {}
				rows[i].online_time = old.online_time or 0
				rows[i].active_time = old.active_time or 0
			end
		end
		data.hourly_stats = rows
	end

	luci.http.write_json(data)
end

-- 上游只注册了这条路由，函数体根本没写：详情页的“上下线记录”一调用
-- 就是 500，表格永远空。fwx 本来就有这个查询，转发即可。
function get_online_offline_records(mac)
	luci.http.prepare_content("application/json")

	local target = normalize_mac(luci.http.formvalue("mac") or mac)
	if target == "" then
		luci.http.write_json({ mac = "", count = 0, records = {} })
		return
	end

	local resp_obj = call_fwx_common("get_online_offline_records", { mac = target })
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({ mac = target, count = 0, records = {} })
	end
end

function get_user_basic_info(mac)
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_user_basic_info"
	req_obj.data = {
		mac = mac
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		traf.merge_user(resp_obj.data)
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({})
	end
end
