-- 终端用户列表（状态菜单）
-- 由 OAF 的用户列表移植而来，只保留「用户列表 + 终端详情」两页。
module("luci.controller.oaf_status_users", package.seeall)

local utl   = require "luci.util"
local fs    = require "nixio.fs"
local jsonc = require "luci.jsonc"

-- 固件特征库的 id->名称索引（559 条）。加载失败不影响页面，只是没有兜底名。
local ok_builtin, builtin_app_names = pcall(require, "luci.oaf_app_names")

-- OAF 自己的计数走 netfilter 钩子，硬件加速开启后大部分包不过协议栈，
-- 速率就会长期是 0。list 上的 V4/V6 分行、厂商名都来自 oaf-flowd 的
-- 快照；模块或采样器不在时 merge_* 什么都不做，页面退回原样。
local ok_tr, traffic = pcall(require, "luci.oaf_lite")
if not ok_tr then traffic = nil end

local SECONDS_PER_DAY = 86400

-- 认不出的应用统一叫「未识别」：id=0 表示采样器一个窗口都没拿到 mark，
-- id>0 但内置名表里没登记，对用户是同一件事，不把 App12 这类内部编号
-- 抛到界面上。
local UNKNOWN_NAME = "未识别"

function index()
	entry({"admin", "status", "oaf_users"},
		alias("admin", "status", "oaf_users", "list"), "用户列表", 8)

	entry({"admin", "status", "oaf_users", "list"},
		cbi("oaf_status/user_list", { hideapplybtn = true, hidesavebtn = true, hideresetbtn = true }), nil).leaf = true

	entry({"admin", "status", "oaf_users", "detail"},
		cbi("oaf_status/user_detail", { hideapplybtn = true, hidesavebtn = true, hideresetbtn = true }), nil).leaf = true

	entry({"admin", "status", "oaf_users", "api", "get_all_users"},        call("api_get_all_users"),        nil).leaf = true
	entry({"admin", "status", "oaf_users", "api", "live_rates"},           call("api_live_rates"),           nil).leaf = true
	entry({"admin", "status", "oaf_users", "api", "get_system_base_info"},  call("api_get_system_base_info"),  nil).leaf = true
	entry({"admin", "status", "oaf_users", "api", "get_class_list"},        call("api_get_class_list"),        nil).leaf = true
	entry({"admin", "status", "oaf_users", "api", "get_user_basic_info"},   call("api_get_user_basic_info"),   nil).leaf = true
	entry({"admin", "status", "oaf_users", "api", "dev_visit_time"},        call("api_dev_visit_time"),        nil).leaf = true
	entry({"admin", "status", "oaf_users", "api", "dev_visit_list"},        call("api_dev_visit_list"),        nil).leaf = true
	entry({"admin", "status", "oaf_users", "api", "get_hourly_stats"},      call("api_get_hourly_stats"),      nil).leaf = true
	entry({"admin", "status", "oaf_users", "api", "app_traffic"},           call("api_app_traffic"),           nil).leaf = true
	entry({"admin", "status", "oaf_users", "api", "set_nickname"},          call("api_set_nickname"),          nil).leaf = true
	entry({"admin", "status", "oaf_users", "api", "history_traffic"},       call("api_history_traffic"),       nil).leaf = true
	entry({"admin", "status", "oaf_users", "api", "proto_traffic"},         call("api_proto_traffic"),         nil).leaf = true
	entry({"admin", "status", "oaf_users", "api", "sampler_info"},          call("api_sampler_info"),          nil).leaf = true
end

-- ---------------------------------------------------------------- 基础工具

-- oaf-lite runs without oafd and without oaf.ko: all APIs the page asks for
-- are served from the C sampler's JSON snapshots in /tmp/oaf-lite.
-- ubus is kept only as a fallback for boxes that also run the original
-- appfilter package, so this plugin can coexist with a stock OAF install.
local LITE_DIR = "/tmp/oaf-lite"
local NICKNAME_FILE = "/etc/oaf-lite/nicknames.json"

local function lite_json(path)
	local f = io.open(path, "r")
	if not f then return nil end
	local body = f:read("*a")
	f:close()
	if not body or body == "" then return nil end
	local ok, obj = pcall(jsonc.parse, body)
	if ok and type(obj) == "table" then return obj end
	return nil
end

local function lite_user(mac)
	local u = lite_json(LITE_DIR .. "/users.json")
	if not (u and type(u.users) == "table") then return nil end
	local want = tostring(mac or ""):upper()
	for _, row in ipairs(u.users) do
		if type(row) == "table" and tostring(row.mac or ""):upper() == want then
			return row
		end
	end
	return nil
end

local function fwx(api, data)
	data = data or {}
	local mac = tostring(data.mac or ""):gsub("^%s+", ""):gsub("%s+$", "")

	if api == "get_all_users" then
		local u = lite_json(LITE_DIR .. "/users.json")
		local list = (u and type(u.users) == "table") and u.users or {}
		local nicks = lite_json(NICKNAME_FILE) or {}
		for _, row in ipairs(list) do
			if type(row) == "table" then
				local nm = nicks[tostring(row.mac or ""):upper()]
				if nm then row.nickname = nm end
			end
		end
		return { code = 2000, data = { list = list, total_num = #list } }

	elseif api == "get_user_basic_info" then
		local row = lite_user(mac)
		if not row then return { code = 4000 } end
		local out = {}
		for k, v in pairs(row) do out[k] = v end
		local nicks = lite_json(NICKNAME_FILE) or {}
		out.nickname = nicks[mac:upper()] or out.nickname or ""
		out.ipv6 = out.ipv6 or out.ip6 or ""
		return { code = 2000, data = out }

	elseif api == "get_system_base_info" then
		local support = 0
		if traffic then
			local ok, s = pcall(traffic.wireless_support)
			if ok then support = s and 1 or 0 end
		end
		return { code = 2000, data = {
			wireless_support = support,
			user_session_enable = 1,
		} }

	elseif api == "class_list" then
		-- #class sections of the feature library, exported by the sampler at
		-- start-up. An edited feature.cfg therefore shows up here at once.
		local meta = lite_json(LITE_DIR .. "/classes.json")
		return { code = 2000, data = {
			class_list = (meta and type(meta.class_list) == "table")
				and meta.class_list or {}
		} }

	elseif api == "set_nickname" then
		local nicks = lite_json(NICKNAME_FILE) or {}
		nicks[mac:upper()] = tostring(data.nickname or "")
		local body = jsonc.stringify(nicks)
		local f = io.open(NICKNAME_FILE, "w")
		if not f then return { code = 4000 } end
		f:write(body or "{}")
		f:close()
		return { code = 2000, data = {} }

	elseif api == "get_hourly_top_apps" or api == "dev_visit_list" then
		-- Hourly traffic, APP charts and visit records all come from the
		-- sampler's hourly.json / apps.json through luci.oaf_lite instead.
		-- Returning 4000 here makes the controller use those read-layer paths.
		return { code = 4000 }
	end

	local resp = utl.ubus("fwx", "common", { api = api, data = data })
	return resp or { code = 4000 }
end

local function normalize_mac(mac)
	if not mac then return "" end
	return (tostring(mac):gsub("^%s+", ""):gsub("%s+$", ""))
end

local function json_out(obj)
	luci.http.prepare_content("application/json")
	luci.http.write_json(obj)
end

-- 取 mac 参数：既支持 /api/xxx/AA:BB:CC 这种路径参数，
-- 也支持 ?mac=AA:BB:CC 的查询参数
local function mac_arg(path_mac)
	return normalize_mac(path_mac or luci.http.formvalue("mac"))
end

-- ---------------------------------------------------------------- 用户列表

-- 上网时长（今日应用会话并集）的批量覆盖函数，定义在下方会话助手函数
-- 之后（那里要用 load_visit_store / session_union）；列表接口在请求期
-- 才调用它，声明提前只是为了拿到这个 upvalue。
local override_usage_times = nil

-- ---------------------------------------------------------------- 列表排序
-- 用户列表统一排序口径：活跃优先、大流量优先。
--   1) 在线、且今日真用过网（有流量/活跃时长/active 标记）的排最前
--   2) 在线但今日没流量的居中，离线设备沉底
--   3) 同档内按今日总流量从大到小
--   4) 再看今日活跃时长、实时速率，最后按 MAC 稳定兜底
-- 活跃判定刻意用「累计」指标而不是瞬时速率：速率每 3 秒就变，拿它分层
-- 会让设备随轮询在两页之间反复横跳，翻页时看着像漏了设备。
-- 另外 today_*_bytes / up_rate / down_rate 本身就是 v4+v6 的合计
-- （前端算 v4 时是用合计减去 today_*6_bytes / *_rate6），不能再把 v6
-- 加一遍，否则有 IPv6 的设备会被算成双倍流量、凭空排到前面。
local function num(v)
	return tonumber(v) or 0
end

local function user_total_bytes(u)
	return num(u.today_up_bytes) + num(u.today_down_bytes)
end

local function user_total_rate(u)
	return num(u.up_rate) + num(u.down_rate)
end

local function user_active_level(u)
	if num(u.online) ~= 1 then return 0 end
	if user_total_bytes(u) > 0 or num(u.today_active_time) > 0 or num(u.active) == 1 then
		return 2
	end
	return 1
end

local function sort_users_by_activity(list)
	table.sort(list, function(a, b)
		local la, lb = user_active_level(a), user_active_level(b)
		if la ~= lb then return la > lb end
		local ba, bb = user_total_bytes(a), user_total_bytes(b)
		if ba ~= bb then return ba > bb end
		local ta, tb = num(a.today_active_time), num(b.today_active_time)
		if ta ~= tb then return ta > tb end
		local ra, rb = user_total_rate(a), user_total_rate(b)
		if ra ~= rb then return ra > rb end
		return tostring(a.mac or "") < tostring(b.mac or "")
	end)
	return list
end

-- ---------------------------------------------------------------- 应用列补齐
-- 没有 fwx/oafd 时，列表原来的兜底只填 mac/ip/在线状态，APP 与 URL 两列整列
-- 是 "--"。oaf-lite 自己已经把「最近访问的域名」和「按字节排行的应用」写进
-- /tmp/oaf-lite/{users,apps}.json，这里读回来补到行上，前端不用区分来源。
local function read_json(path)
	local f = io.open(path, "r")
	if not f then return nil end
	local body = f:read("*a")
	f:close()
	if not body or body == "" then return nil end
	local ok, d = pcall(jsonc.parse, body)
	if not ok or type(d) ~= "table" then return nil end
	return d
end

local function fill_app_columns(list)
	if type(list) ~= "table" or #list == 0 then return end

	local by_mac = {}
	local uj = read_json("/tmp/oaf-lite/users.json")
	if uj and type(uj.users) == "table" then
		for _, u in ipairs(uj.users) do
			if type(u) == "table" and u.mac then
				by_mac[tostring(u.mac):upper()] = u
			end
		end
	end

	local apps_by_mac = {}
	local aj = read_json("/tmp/oaf-lite/apps.json")
	if aj and type(aj.clients) == "table" then
		for mac, arr in pairs(aj.clients) do
			if type(arr) == "table" then
				local out = {}
				for _, a in ipairs(arr) do
					local id = tonumber(a.id) or 0
					if type(a) == "table" and id > 0 then
						out[#out + 1] = {
							id    = tostring(id),
							name  = a.name or "",
							bytes = (tonumber(a.up) or 0) + (tonumber(a.down) or 0),
						}
					end
				end
				table.sort(out, function(x, y) return x.bytes > y.bytes end)
				while #out > 5 do table.remove(out) end
				apps_by_mac[tostring(mac):upper()] = out
			end
		end
	end

	for _, row in ipairs(list) do
		local key = tostring(row.mac or ""):upper()
		local u = by_mac[key]
		if u then
			row.app_id = tonumber(u.app_id) or 0
			row.app    = u.app or ""
			row.url    = u.url or ""
			if row.app_id > 0 then
				row.app_icon = tostring(row.app_id)
			end
		end
		local apps = apps_by_mac[key]
		if apps and #apps > 0 and not (type(row.applist) == "table" and #row.applist > 0) then
			row.applist = apps
		end
	end
end

function api_get_all_users()
	local page      = tonumber(luci.http.formvalue("page")) or 1
	local page_size = tonumber(luci.http.formvalue("page_size")) or 20
	local flag      = tonumber(luci.http.formvalue("flag")) or 3

	-- 排序必须跨页生效，所以先一次取回全部设备，排完再按请求的页切片。
	-- oafd 的 get_all_users 上限 1024 台，家用/宿舍场景足够；取全量失败时
	-- 退回原来的单页请求，保证列表不会开天窗。
	local ALL_USERS_LIMIT = 1024
	local resp = fwx("get_all_users", { flag = flag, page = 1, page_size = ALL_USERS_LIMIT })
	if not (resp and resp.code == 2000 and type(resp.data) == "table") then
		resp = fwx("get_all_users", { flag = flag, page = page, page_size = page_size })
	end

	if resp and resp.code == 2000 and type(resp.data) == "table" then
		local list = type(resp.data.list) == "table" and resp.data.list or {}
		if traffic and #list > 0 then
			pcall(traffic.merge_list, list)
		end
		-- 上网时长统一为会话并集口径，与详情页/饼图/访问记录一致
		if override_usage_times and #list > 0 then
			pcall(override_usage_times, list)
		end
		pcall(fill_app_columns, list)
		sort_users_by_activity(list)

		local total = num(resp.data.total_num)
		if total < #list then total = #list end
		local total_page = math.max(1, math.ceil(total / page_size))
		local out = {}
		for i = 1, page_size do
			local row = list[(page - 1) * page_size + i]
			if row then out[#out + 1] = row end
		end
		json_out({ data = {
			list       = out,
			total_num  = total,
			total_page = total_page,
			page       = page,
			page_size  = page_size,
		} })
	else
		-- fwx/oafd 不可用（appfilter 包未装、oafd 未启动或 ubus 超时）的兜底：
		-- 直接用 oaf-flowd 的设备表出列表。流量/速率/在线状态/上网时长/OUI
		-- 厂商都齐全；APP 识别相关字段（app_id/app/app_icon/nickname）只能
		-- 留空，装回 appfilter 包或 oafd 恢复后自动回到主路。
		local list, total = {}, 0
		if traffic then
			local ok, idx = pcall(traffic.index)
			if ok and type(idx) == "table" then
				for mac, c in pairs(idx) do
					if type(c) == "table" and mac and mac ~= "" then
						total = total + 1
						list[total] = {
							mac      = mac,
							ip       = "",
							hostname = c.name or "",
							online   = ((c.flows or 0) > 0) and 1 or 0,
						}
						-- 信号列：无线客户端补 libiwinfo 的 RSSI，有线设备
						-- 留空显示 --（信号列开关来自 system_base_info）
						if traffic then
							local ok, w = pcall(traffic.wireless_user, mac)
							if ok and w and w.rssi then
								list[total].rssi = w.rssi
							end
						end
					end
				end
			end
		end
		if total > 0 then
			if traffic then pcall(traffic.merge_list, list) end
			if override_usage_times then pcall(override_usage_times, list) end
			pcall(fill_app_columns, list)
			sort_users_by_activity(list)
		end
		local total_page = math.max(1, math.ceil(total / page_size))
		local out = {}
		for i = 1, page_size do
			local row = list[(page - 1) * page_size + i]
			if row then out[#out + 1] = row end
		end
		json_out({ data = { list = out, total_num = total, total_page = total_page, page = page } })
	end
end

-- 首页快通道：1 秒一次，只给「上行速率 / 下行速率 / 今日流量」三项。
-- 数据来自 oaf-flowd 的 stats.json，和慢通道 merge 后的数字是同一份，
-- 两条路不会互相打脸；一次只有几百字节，也不用走 ubus。
--
-- 只回传当前这一页的设备：这个接口每秒被叫一次，设备一多（宿舍/办公室
-- 几十台）整张表全量回传就白搬了 —— 页面上的节点只认眼前这 20 行。
-- 前端按 data-mac 把在屏 MAC 拼成 macs= 传上来，这里按集合过滤；
-- 不传（老版本缓存、手工调试）时退回全量，行为不变。
function api_live_rates()
	if not traffic then json_out({ list = {} }); return end

	local ok, idx = pcall(traffic.index)
	if not ok or type(idx) ~= "table" then json_out({ list = {} }); return end

	local want
	local raw = luci.http.formvalue("macs")
	if raw and raw ~= "" then
		want = {}
		for m in raw:gmatch("[^,]+") do
			want[normalize_mac(m):upper()] = true
		end
	end

	local out = {}
	for mac, c in pairs(idx) do
		if type(c) == "table" and (not want or want[mac]) then
			out[#out + 1] = {
				mac               = mac,
				ip6               = c.ip6 or "",
				up_rate           = c.rate_up or 0,
				down_rate         = c.rate_down or 0,
				up_rate6          = c.rate_up6 or 0,
				down_rate6        = c.rate_down6 or 0,
				today_up_bytes    = c.today_up or 0,
				today_down_bytes  = c.today_down or 0,
				today_up6_bytes   = c.today_up6 or 0,
				today_down6_bytes = c.today_down6 or 0,
				today_active_time = c.day_active or 0,
				flows             = c.flows or 0,
			}
		end
	end

	json_out({ list = out })
end

-- 列表里「会话数 / 信号」两列是否显示，取决于这两个开关。
-- 原版还返回一堆别的字段，这里只留用得上的。
function api_get_system_base_info()
	local resp = fwx("get_system_base_info", {})
	local data = (resp and resp.code == 2000 and type(resp.data) == "table") and resp.data or {}

	local support = data.wireless_support
	-- fwx 不在（appfilter 未装、oafd 挂了）时自行探测无线能力：前端靠
	-- wireless_support 这个键决定画不画信号列，缺了它整列就消失。
	if support == nil and traffic then
		local ok, sup = pcall(traffic.wireless_support)
		if ok then
			support = sup
		end
	end

	json_out({
		user_session_enable = data.user_session_enable or 0,
		wireless_support    = support
	})
end

function api_get_class_list()
	local resp = fwx("class_list", {})
	if resp and resp.code == 2000 and type(resp.data) == "table" then
		json_out(resp.data)
	else
		json_out({ class_list = {} })
	end
end

-- ---------------------------------------------------------------- 终端详情

-- 权威名字表由 oaf-lite 直接从明文特征库导出到 tmpfs（app_names.json）：
-- 用户改了 feature.cfg，页面立刻跟着变。第一个路径在 overlay 上，是
-- 「学到一次就落盘」的增量保存位置，跨重启累积；读的时候 tmpfs 那份
-- 后加载、覆盖同 id，保证特征库始终是权威。
local APP_NAME_FILES = {
	"/etc/oaf-lite/app_names.json",
	"/tmp/oaf-lite/app_names.json",
}

local function read_json_file(path)
	local f = io.open(path, "r")
	if not f then return nil end
	local body = f:read("*a")
	f:close()
	if not body or body == "" then return nil end
	local ok, data = pcall(jsonc.parse, body)
	if not ok or type(data) ~= "table" then return nil end
	return data
end

-- appid -> 应用名。fwx 的库里只存 id，名字是它跟云端问的，学到一次
-- 就落盘，历史记录里的老应用也能显示中文名；没学到的用内置表兜底，
-- 学到的名字（可能改名/更新）优先。
local function load_learned_names()
	local map = {}
	for _, path in ipairs(APP_NAME_FILES) do
		local data = read_json_file(path)
		if type(data) == "table" then
			for id, name in pairs(data) do
				if type(name) == "string" and name ~= "" then
					map[tostring(id)] = name
				end
			end
		end
	end
	return map
end

local function load_app_names()
	local map = {}
	if ok_builtin and type(builtin_app_names) == "table" then
		for id, name in pairs(builtin_app_names) do
			map[tostring(id)] = name
		end
	end
	for id, name in pairs(load_learned_names()) do
		map[id] = name
	end
	return map
end

-- 只把 fwx 学到的增量写回磁盘；内置表不落盘，避免整表反复重写。
local function save_app_names(map)
	local body = jsonc.stringify(map)
	for _, path in ipairs(APP_NAME_FILES) do
		local f = io.open(path, "w")
		if f then
			f:write(body)
			f:close()
			return
		end
	end
end

-- 访问记录只保留最近 30 天。主数据源是采样器的 apps.json（见
-- api_dev_visit_list）：每个应用的小时活跃秒数 + 字节，按 2 KiB 门槛过滤。
-- 下面这份落盘文件是可选的「历史会话」兜底，供应用活跃数据还没攒够时
-- 的饼图/柱状图使用；没有 oafd，也没有 client.db。
local VISIT_KEEP_SECONDS = 30 * SECONDS_PER_DAY
-- 写在本插件自己的 overlay 目录下，不读其它固件的 /etc/oaf/data，
-- 避免刷机后把上一任安装的 30 天历史带回来。
local VISIT_STORE_FILES = {
	"/etc/oaf-lite/visits.json",
}

local function load_visit_store()
	for _, path in ipairs(VISIT_STORE_FILES) do
		local data = read_json_file(path)
		if data and type(data.list) == "table" then return data.list end
	end
	return nil
end

-- 同一台设备的去重访问会话：落盘的 30 天记录 + fwx 当天列表。
-- 访问记录列表、应用统计饼图、常用 APP 柱状图三处共用这一份数据——
-- fwx 自己的 dev_visit_time 和 get_hourly_top_apps 各算各的（同一台
-- 设备能差出几倍，oafd 重启还会把小时统计清零），跟访问记录列表都对
-- 不上，页面上的数字互相矛盾；统一从会话汇总后三个视图必然一致。
local function merged_sessions(target, cutoff)
	local names = load_app_names()
	local merged = {}
	local want = target:lower()

	-- 同一次访问在两边都出现时取更长的那个，避免 flowd 15 秒的同步间隔
	-- 让「在线中」的那条看起来刚打开
	local function put(rec)
		local ft = tonumber(rec.ft) or 0
		if ft < cutoff then return end
		local id  = tonumber(rec.id) or 0
		local lt  = tonumber(rec.lt) or ft
		local tt  = tonumber(rec.tt) or 0
		local key = string.format("%d:%d", id, ft)
		local cur = merged[key]
		if not cur then
			merged[key] = {
				id = id, ft = ft, lt = lt, tt = tt,
				online = tonumber(rec.online) or 0,
				icon = rec.icon,
				name = rec.name,
			}
			return
		end
		if lt > cur.lt then cur.lt = lt end
		if tt > cur.tt then cur.tt = tt end
		if tonumber(rec.online) == 1 then cur.online = 1 end
		if (not cur.name or cur.name == "") and rec.name and rec.name ~= "" then
			cur.name = rec.name
		end
	end

	local stored = load_visit_store()
	if stored then
		for _, rec in ipairs(stored) do
			if type(rec) == "table" and normalize_mac(rec.mac):lower() == want then
				local id = tonumber(rec.id) or 0
				put({ id = id, ft = rec.ft, lt = rec.lt, tt = rec.tt,
					online = 0, name = names[tostring(id)] })
			end
		end
	end

	local meta
	local resp = fwx("dev_visit_list", { mac = target, page = 1, page_size = 500 })
	if resp and resp.code == 2000 and type(resp.data) == "table"
		and type(resp.data.list) == "table" then
		meta = resp.data
		local learned = false
		local learnedMap = load_learned_names()
		for _, rec in ipairs(resp.data.list) do
			if type(rec) == "table" then
				local id = tonumber(rec.id) or 0
				if type(rec.name) == "string" and rec.name ~= "" then
					if learnedMap[tostring(id)] ~= rec.name then
						learnedMap[tostring(id)] = rec.name
						learned = true
					end
				end
				put(rec)
			end
		end
		if learned then save_app_names(learnedMap) end
	end

	local all = {}
	for _, rec in pairs(merged) do
		if not rec.name or rec.name == "" then
			rec.name = names[tostring(rec.id)]
		end
		all[#all + 1] = rec
	end
	-- 最近的访问排在最前
	table.sort(all, function(a, b)
		if (a.lt or 0) ~= (b.lt or 0) then return (a.lt or 0) > (b.lt or 0) end
		return (a.ft or 0) > (b.ft or 0)
	end)
	return all, meta, (stored ~= nil)
end

-- 「今天 0 点」必须按采样器用的时区算。
-- 采样器的日文件 /tmp/oaf-lite/day/YYYY-MM-DD.json 和小时桶都是按
-- /etc/config/oaf-lite 的 option tz（默认 8）切的；这里原来用 os.date/os.time
-- 走系统时区，本机 /etc/TZ 是 GMT0，于是「今天」比采样器晚 8 小时开始，
-- 访问记录、历史日期的边界全部错位。
-- 采样器模块提供了一套与时区无关的实现；模块不在时退回原来的写法。
local function tz_hours()
	if traffic and traffic.tz_hours then
		local ok, v = pcall(traffic.tz_hours)
		if ok and tonumber(v) then return tonumber(v) end
	end
	return 8
end

local function tz_seconds() return tz_hours() * 3600 end

local function lt_date(fmt, ts)
	return os.date("!" .. fmt, (ts or os.time()) + tz_seconds())
end

local function lt_hour(ts)
	local s = (ts or os.time()) + tz_seconds()
	return math.floor((s % 86400) / 3600)
end

local function today_start()
	local off = tz_seconds()
	return math.floor((os.time() + off) / 86400) * 86400 - off
end

-- 配置时区的年月日 -> 真实 epoch（与时区无关的民用历算法）
local function lt_epoch(y, mo, d)
	if mo <= 2 then y = y - 1 end
	local era = math.floor(y / 400)
	local yoe = y - era * 400
	local mp  = (mo + 9) % 12
	local doy = math.floor((153 * mp + 2) / 5) + d - 1
	local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
	local days = era * 146097 + doe - 719468
	return days * 86400 - tz_seconds()
end

-- 设备级「上网时长」：把会话的 [开始, 结束] 区间合并去重后求和。
-- 按应用求和（饼图口径）会把并行长连接的同一分钟算两遍——PC 上 QQ 和
-- 拼音一起挂 4 个小时，饼图合计 9 小时；并集只算一次，才是设备的真实
-- 占用。手机上会话基本不重叠，并集 ≈ 饼图合计，两个数字互相印证。
-- 会话窗口本身来自流量判定，天然 ≤ fwx 的在线时长。
local function session_union(sessions)
	local ivs = {}
	for _, rec in ipairs(sessions) do
		local ft = tonumber(rec.ft) or 0
		local lt = tonumber(rec.lt) or ft
		if ft > 0 and lt > ft then
			ivs[#ivs + 1] = { ft, lt }
		end
	end
	table.sort(ivs, function(a, b) return a[1] < b[1] end)
	local total, cs, ce = 0, nil, nil
	for _, iv in ipairs(ivs) do
		if cs == nil then
			cs, ce = iv[1], iv[2]
		elseif iv[1] <= ce then
			if iv[2] > ce then ce = iv[2] end
		else
			total = total + (ce - cs)
			cs, ce = iv[1], iv[2]
		end
	end
	if cs ~= nil then total = total + (ce - cs) end
	return total
end

function api_get_user_basic_info(mac)
	local target = mac_arg(mac)
	if target == "" then json_out({}); return end

	local resp = fwx("get_user_basic_info", { mac = target })
	if resp and resp.code == 2000 and type(resp.data) == "table" then
		if traffic then
			pcall(traffic.merge_user, resp.data)
		end
		-- 上网时长（活跃口径）：flowd 1.8.0 的 day_active 只在某一轮采样
		-- 里设备真的搬了超过心跳阈值的字节才计时，挂机的 QQ/微信/输入法
		-- 长连接一秒都拿不到。merge_user 无条件写它（0 = 还没真正用过）。
		-- 只有采样器根本没有这台设备时（刚接入、tmpfs 过期）才退回
		-- 会话并集兜底。
		local haveFlowd = false
		if traffic then
			local ok, c = pcall(traffic.client, target)
			haveFlowd = ok and type(c) == "table"
		end
		if not haveFlowd then
			local usage = session_union(merged_sessions(target, today_start()))
			if usage > 0 then
				resp.data.today_active_time = usage
			end
		end
		-- 今日上下行不用再叠加 *6 字段：flowd 的 DayDown 本来就是 v4+v6
		-- 的全量，DayDown6 只是「其中有多少走 v6」的子集口径（列表页拿
		-- 它单独分行显示），叠上去会把 v6 算两遍。
		json_out(resp.data)
	else
		-- fwx 不在时的兜底（appfilter 未装 / oafd 挂了）：流量、速率、
		-- 在线状态、今日上网时长来自 oaf-flowd，无线信息来自 libiwinfo，
		-- 字段名与 fwx 的 get_user_basic_info 完全一致，前端不用分支。
		-- 今日在线时长由 merge_user 用 flowd 的在网秒数补齐，并保证
		-- 不小于上网时长；装回 appfilter 后会自动取 fwx 与 flowd 的较大值。
		local d = { mac = target, online = 0 }
		if traffic then
			pcall(traffic.merge_user, d)
			-- 与列表页同一判定：conntrack 里还有这条设备的流就是在网。
			-- 无线客户端在下面 iwinfo 命中后也会置 1，两条路一致。
			d.online = ((d.flows or 0) > 0) and 1 or 0
		end
		if traffic then
			local ok, w = pcall(traffic.wireless_user, target)
			if ok and w then
				d.band        = w.band
				d.wifi_ifname = w.ifname
				d.tx_rate     = w.tx_rate
				d.rx_rate     = w.rx_rate
				d.rssi        = w.rssi
				d.online      = 1
			end
		end
		json_out(d)
	end
end

-- 列表页批量覆盖：与详情页同口径——flowd 的活跃秒数是权威（0 = 还没
-- 真正用过），采样器没有这台设备时退回「落盘会话 + fwx 实时会话」的
-- 并集（oafd 重启后内存里只有重启后的会话，client.db 只落已关闭的会话，
-- 两边单独用都缺一块）。
override_usage_times = function(list)
	if type(list) ~= "table" then return end
	local t0 = today_start()
	for _, u in ipairs(list) do
		if type(u) == "table" and u.mac then
			local target = normalize_mac(u.mac)
			if target ~= "" then
				local haveFlowd = false
				if traffic then
					local ok, c = pcall(traffic.client, target)
					haveFlowd = ok and type(c) == "table"
				end
				if not haveFlowd then
					local usage = session_union(merged_sessions(target, t0))
					if usage > 0 then u.today_active_time = usage end
				end
			end
		end
	end
end

-- 应用统计饼图：今天的 APP 活跃使用时长。
-- 挂机的长连接（QQ/微信/输入法的心跳）不算时间：flowd 每轮采样里应用
-- 真的搬了超过心跳阈值的字节才计一轮。数据源 oaf-flowd 1.8.0 的
-- apps.json「a」字段；采样器没有活跃数据（刚重启、旧版本）时退回访问
-- 会话的口径——那是"连接挂着"的时长，数字会明显偏大。
function api_dev_visit_time(mac)
	local target = mac_arg(mac)
	if target == "" then json_out({}); return end

	local names = load_app_names()

	local act
	if traffic then
		local ok, v = pcall(traffic.client_app_active, target)
		if ok then act = v end
	end
	if act and next(act.apps) ~= nil then
		local merged = {}
		for id, t in pairs(act.apps) do
			-- 仅显示已知特征应用：conntrack mark 为 0（识别内核不在、或该
			-- 流还没被分类）、以及内置 559 条表之外认不出的 appid，直接
			-- 跳过——页面上不出现说不清来路的「其他」大扇区
			local nm = id > 0 and names[tostring(id)] or nil
			if nm then
				local slot = merged[id]
				if not slot then
					slot = { id = id, t = 0, name = nm }
					merged[id] = slot
				end
				slot.t = slot.t + t
			end
		end
		local out = {}
		for _, slot in pairs(merged) do out[#out + 1] = slot end
		table.sort(out, function(a, b) return a.t > b.t end)
		json_out(out)
		return
	end

	local all = merged_sessions(target, today_start())
	local sums, order = {}, {}
	for _, rec in ipairs(all) do
		local id = tonumber(rec.id) or 0
		-- 同主路：内置表认不出、记录里也没有名字的 appid 一律不算已知应用
		local nm = (id > 0 and names[tostring(id)])
			or (rec.name and rec.name ~= "" and rec.name)
			or nil
		if id > 0 and nm then
			local slot = sums[id]
			if not slot then
				slot = { id = id, icon = rec.icon, name = nm, t = 0 }
				sums[id] = slot
				order[#order + 1] = id
			end
			slot.t = slot.t + (tonumber(rec.tt) or 0)
		end
	end
	table.sort(order, function(a, b) return sums[a].t > sums[b].t end)
	local out = {}
	for _, id in ipairs(order) do out[#out + 1] = sums[id] end
	json_out(out)
end

local function visit_ts(rec)
	local ft = tonumber(rec.ft) or 0
	local lt = tonumber(rec.lt) or 0
	-- 老记录可能只带其中一个时间，取较新的那个当「最近访问」更稳
	return (lt > ft) and lt or ft
end

function api_dev_visit_list(mac)
	local target = mac_arg(mac)
	if target == "" then json_out({ list = {}, total_num = 0, total_page = 1, page = 1 }); return end

	local req_page = tonumber(luci.http.formvalue("page")) or 1
	local req_size = tonumber(luci.http.formvalue("page_size")) or 15
	if req_page < 1 then req_page = 1 end
	if req_size < 1 then req_size = 15 end
	if req_size > 200 then req_size = 200 end

	-- 与「今日常用 APP」同源：apps.json 的活跃秒数 + 字节，按小时桶
	-- 2 KiB 门槛过滤。挂机心跳、特征库认不出的应用都不进表。
	local all, meta, persisted = {}, nil, true
	local visits = traffic and traffic.client_app_visits(target)
	if type(visits) == "table" then
		local names = load_app_names()
		local now = os.time()
		for _, v in ipairs(visits) do
			local nm = (v.id > 0 and names[tostring(v.id)]) or nil
			if nm then
				all[#all + 1] = {
					id = v.id, name = nm,
					ft = v.ft, lt = v.lt, tt = v.tt,
					bytes = v.bytes,
					online = (now - v.lt <= 120) and 1 or 0,
				}
			end
		end
		table.sort(all, function(x, y)
			if x.lt ~= y.lt then return x.lt > y.lt end
			return (x.bytes or 0) > (y.bytes or 0)
		end)
	else
		all, meta, persisted = merged_sessions(target, os.time() - VISIT_KEEP_SECONDS)
	end

	local total_num  = #all
	local total_page = math.max(1, math.ceil(total_num / req_size))
	if req_page > total_page then req_page = total_page end
	local out, from = {}, (req_page - 1) * req_size + 1
	local to = math.min(total_num, from + req_size - 1)
	for i = from, to do out[#out + 1] = all[i] end

	json_out({
		mac        = target,
		ip         = meta and meta.ip or nil,
		hostname   = meta and meta.hostname or nil,
		list       = out,
		total_num  = total_num,
		total_page = total_page,
		page       = req_page,
		page_size  = req_size,
		keep_days  = 1,
		persisted  = persisted,
	})
end

-- 「今日流量」和「今日常用 APP」两张图共用这一份 24 小时数据
-- 「今日流量」和「今日常用 APP」两张图共用这一份 24 小时数据。
-- 流量/在线/活跃时长沿用 fwx 的 get_hourly_top_apps；每个小时的 APP 明细
-- 改为从访问会话按小时聚合：fwx 自带的 apps 数组跟访问记录列表对不上
-- （oafd 重启还会把重启前几个小时的小时统计清零），导致柱状图与饼图、
-- 列表互相矛盾。只查今天：带 date 查历史日期会让 oafd 崩掉（上游
-- use-after-free），历史数据走 api_history_traffic 直接读文件。
function api_get_hourly_stats(mac)
	local target = mac_arg(mac)
	if target == "" then
		json_out({ mac = "", date = 0, is_today = 1, hourly_stats = {} })
		return
	end

	local resp = fwx("get_hourly_top_apps", { mac = target })
	local data
	if resp and resp.code == 2000 and type(resp.data) == "table"
		and type(resp.data.hourly_stats) == "table" then
		data = resp.data
	else
		data = { mac = target, date = 0, is_today = 1, hourly_stats = {} }
	end
	local names = load_app_names()

	-- 会话按小时切片：拼音/QQ 这类长连接一挂就是几个小时，整段塞进开始
	-- 小时会出现「一个小时内用了 3H」的怪柱子。按每小时的重叠秒数占比
	-- 分摊，任何一小时都不超过 3600 秒，各小时之和仍等于饼图/访问记录
	-- 列表的合计。
	--
	-- 优先用 flowd 的活跃秒数（1.8.0）：每轮采样里应用真的搬了超过心跳
	-- 阈值的字节才计一轮，挂机长连接在这里一秒都没有，单小时也永远不会
	-- 超过 3600。采样器拿不到活跃数据时才退回会话切片。
	local hourApps = {}  -- [hour][appid] = {appid, icon, name, time}
	local act
	if traffic then
		local ok, v = pcall(traffic.client_app_active, target)
		if ok then act = v end
	end
	if act and next(act.hours) ~= nil then
		for h, row in pairs(act.hours) do
			local bucket = hourApps[h]
			if not bucket then bucket = {}; hourApps[h] = bucket end
			for id, secs in pairs(row) do
				-- 与饼图同一规则：无名的 id（含 mark=0）并进「其他」
				local nm = id > 0 and names[tostring(id)] or nil
				local key = nm and id or 0
				local slot = bucket[key]
				if not slot then
					slot = { appid = key, time = 0, name = nm or UNKNOWN_NAME }
					bucket[key] = slot
				end
				slot.time = slot.time + secs
			end
		end
	else
		local function add_app_hour(h, rec, secs)
		if secs <= 0 then return end
		local id = tonumber(rec.id) or 0
		local row = hourApps[h]
		if not row then row = {}; hourApps[h] = row end
		local slot = row[id]
		if not slot then
			slot = { appid = id, icon = rec.icon, name = rec.name, time = 0 }
			row[id] = slot
		end
		slot.time = slot.time + secs
		if (not slot.name or slot.name == "") and rec.name and rec.name ~= "" then
			slot.name = rec.name
		end
	end
	for _, rec in ipairs(merged_sessions(target, today_start())) do
		local id = tonumber(rec.id) or 0
		if id > 0 then
			local ft = tonumber(rec.ft) or 0
			local lt = tonumber(rec.lt) or ft
			if lt < ft then lt = ft end
			local span = lt - ft
			local tt = tonumber(rec.tt) or span
			if span <= 0 then
				-- 没有跨度可言（瞬时记录），整段记入开始小时
				add_app_hour(lt_hour(ft), rec, tt)
			else
				-- 切出与每个小时重叠的段，按时长占比分摊 tt，取整余数记到
				-- 最后一段，保证合计守恒。小时边界按配置时区对齐采样器的桶。
				local segs = {}
				local off = tz_seconds()
				local cur = ft
				while cur < lt do
					local hb = math.floor((cur + off) / 3600) * 3600 - off
					local seg = (lt < hb + 3600) and lt or (hb + 3600)
					segs[#segs + 1] = { hour = lt_hour(cur), ov = seg - cur }
					cur = seg
				end
				local allocated = 0
				for i, sg in ipairs(segs) do
					local share
					if i == #segs then
						share = tt - allocated
						if share < 0 then share = 0 end
					else
						share = math.floor(tt * sg.ov / span + 0.5)
						allocated = allocated + share
					end
					add_app_hour(sg.hour, rec, share)
				end
			end
		end
	end
	end -- else（无活跃数据时的会话切片）

	-- 每应用每小时的字节数，与「今日常用 APP」的活跃秒数同一份 apps.json。
	-- 无名 id 与饼图一样并进兜底桶 0，柱状图会把这个桶过滤掉。
	if traffic then
		local ok, ab = pcall(traffic.client_app_bytes, target)
		if ok and type(ab) == "table" then
			for h, row in pairs(ab) do
				local hh = tonumber(h) or 0
				local bucket = hourApps[hh]
				if not bucket then bucket = {}; hourApps[hh] = bucket end
				for id, b in pairs(row) do
					local aid = tonumber(id) or 0
					local nm = aid > 0 and names[tostring(aid)] or nil
					local key = nm and aid or 0
					local slot = bucket[key]
					if not slot then
						slot = { appid = key, time = 0, bytes = 0, name = nm or UNKNOWN_NAME }
						bucket[key] = slot
					end
					slot.bytes = (slot.bytes or 0) + (tonumber(b) or 0)
				end
			end
		end
	end

	-- fwx 的小时数据按小时索引，供在线/活跃时长取用
	local fwxHour = {}
	for _, hs in ipairs(data.hourly_stats) do
		fwxHour[tonumber(hs.hour) or -1] = hs
	end

	-- 流量桶：优先采样器的每客户端小时桶（与今日总量在 flowd 里同一处
	-- 记账、跨重启可恢复）。fwx 的小时流量挂在 netfilter 钩子上，oafd
	-- 重启就清零（今天 09:27 重启后柱状图只剩 1.5MB，而设备实际下行
	-- 154M），硬件卸载的流量也记不全，所以只作兜底。
	local fh
	if traffic then
		local ok, v = pcall(traffic.client_hours, target)
		if ok then fh = v end
	end

	-- 固定输出完整的 0..23 小时，保证柱状图 X 轴完整
	local final = {}
	for h = 0, 23 do
		local src = fwxHour[h]
		local apps = {}
		local row = hourApps[h]
		if row then
			local ids = {}
			for aid in pairs(row) do ids[#ids + 1] = aid end
			table.sort(ids, function(a, b)
				local ba, bb = row[a].bytes or 0, row[b].bytes or 0
				if ba ~= bb then return ba > bb end
				return row[a].time > row[b].time
			end)
			for _, aid in ipairs(ids) do
				local slot = row[aid]
				slot.bytes = slot.bytes or 0
				apps[#apps + 1] = slot
			end
		end
		local tr
		if fh then
			local slot = fh[h + 1]
			tr = { up_bytes = (slot and slot.up) or 0, down_bytes = (slot and slot.down) or 0 }
		else
			tr = (src and type(src.traffic) == "table" and src.traffic)
				or { up_bytes = 0, down_bytes = 0 }
		end
		final[#final + 1] = {
			hour        = h,
			apps        = apps,
			traffic     = tr,
			online_time = (src and src.online_time) or 0,
			active_time = (src and src.active_time) or 0,
		}
	end
	data.hourly_stats = final
	data.is_today = 1
	json_out(data)
end

-- 按应用的今日流量（含硬件加速的部分）
-- 数据来自 oaf-flowd 的 apps.json：appid 取自 conntrack 的 mark，字节取自
-- conntrack 计数（PPE 卸载后会继续回写），所以长连接不会只算开头几个包。
-- fwx 的 get_hourly_top_apps 只给时长，且依赖 netfilter 钩子，这里两样都补上。
function api_app_traffic(mac)
	local target = mac_arg(mac)
	if target == "" or not traffic then
		json_out({ mac = target, apps = {} })
		return
	end
	-- apps.json 里只有 appid。把内置特征库名表附上，表格不必再发一轮请求，
	-- 也和详情图、访问记录里的应用名保持同一套叫法。
	local apps = traffic.app_traffic(target) or {}
	local names = load_app_names()
	for _, a in ipairs(apps) do
		local id = tonumber(a.id) or 0
		if id == 0 then
			a.name = "未识别"
		else
			a.name = names[tostring(id)] or a.name or nil
		end
	end
	json_out({ mac = target, apps = apps })
end

function api_set_nickname()
	local target = normalize_mac(luci.http.formvalue("mac"))
	local nickname = luci.http.formvalue("nickname") or ""

	if target == "" then json_out({ code = 1, message = "invalid mac" }); return end

	local resp = fwx("set_nickname", { mac = target, nickname = nickname })
	if resp and resp.code == 2000 then
		json_out(resp.data or {})
	else
		json_out({ code = 1, message = "failed" })
	end
end

-- ---------------------------------------------------------------- 历史流量
-- 日汇总由 oaf-lite 的采样器写在同一目录：
--   /tmp/oaf-lite/day/YYYY-MM-DD.json
--   { clients = [ { mac, day_up, day_down, hours = [...] } ], apps = {...} }
-- 今天的文件也在实时更新，所以今天和历史用同一套读法，全程不碰 ubus/oafd。
-- 目录在 tmpfs 上：重启当天从 0 重新累计，本次开机期间的历史天文件保留。
local LITE_DAY_DIR = LITE_DIR .. "/day"

local function read_flow_day(mac_addr, ts)
	-- 采样器的日文件按 option tz 切日，取日期也必须用同一个时区，
	-- 否则本地时间 0~8 点之间会去翻前一天的文件，今日流量显示成 0。
	local day = lt_date("%Y-%m-%d", ts)
	local raw = fs.readfile(string.format("%s/%s.json", LITE_DAY_DIR, day))
	if not raw or raw == "" then return nil end
	local ok, obj = pcall(jsonc.parse, raw)
	if not ok or type(obj) ~= "table" or type(obj.clients) ~= "table" then return nil end
	local want = mac_addr:lower()
	for _, c in ipairs(obj.clients) do
		if type(c) == "table" then
			local mac = tostring(c.mac or c.key or ""):lower()
			if mac == want then
				return (tonumber(c.day_up) or 0), (tonumber(c.day_down) or 0)
			end
		end
	end
	return 0, 0   -- 有当日文件，但这台设备当天没上网
end

local function read_day_file(mac_addr, ts)
	local up, down = read_flow_day(mac_addr, ts)
	if up then return up, down, true end
	return 0, 0, false
end

-- 今天和以前都读采样器的日文件，is_today 只是保留签名
local function day_traffic(mac_addr, ts, is_today)
	return read_day_file(mac_addr, ts)
end

function api_history_traffic(mac)
	local target = mac_arg(mac)
	local mode   = luci.http.formvalue("mode") or "1d"

	if target == "" then
		json_out({ code = 1, message = "invalid mac", days = {}, summary = { up_bytes = 0, down_bytes = 0, total_bytes = 0 } })
		return
	end

	local today = today_start()
	local stamps = {}

	-- 页面上固定看「最近 30 天」，这里按 mode 生成日期列表；
	-- 1d / 7d / date 留着，脚本调接口时还能用
	if mode == "30d" then
		for i = 29, 0, -1 do
			stamps[#stamps + 1] = today - i * SECONDS_PER_DAY
		end
	elseif mode == "7d" then
		for i = 6, 0, -1 do
			stamps[#stamps + 1] = today - i * SECONDS_PER_DAY
		end
	elseif mode == "date" then
		local d = luci.http.formvalue("date") or ""
		local y, m, dd = d:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)$")
		if not y then
			json_out({ code = 1, message = "invalid date", days = {}, summary = { up_bytes = 0, down_bytes = 0, total_bytes = 0 } })
			return
		end
		local ts = lt_epoch(tonumber(y), tonumber(m), tonumber(dd))
		if not ts or ts > today then
			json_out({ code = 1, message = "future date", days = {}, summary = { up_bytes = 0, down_bytes = 0, total_bytes = 0 } })
			return
		end
		stamps[1] = ts
	else
		mode = "1d"
		stamps[1] = today
	end

	local days, total_up, total_down = {}, 0, 0
	for _, ts in ipairs(stamps) do
		local up, down, has = day_traffic(target, ts, ts >= today)
		total_up   = total_up   + up
		total_down = total_down + down
		days[#days + 1] = {
			date        = ts,
			date_str    = lt_date("%Y-%m-%d", ts),
			up_bytes    = up,
			down_bytes  = down,
			total_bytes = up + down,
			has_data    = has and 1 or 0
		}
	end

	json_out({
		code    = 0,
		mode    = mode,
		mac     = target,
		days    = days,
		summary = {
			up_bytes    = total_up,
			down_bytes  = total_down,
			total_bytes = total_up + total_down
		}
	})
end

-- ---------------------------------------------------------------- 协议分布
-- 六类协议图例（TLS / HTTP / QUIC / FAILED / DNS / OTHER）。数字来自
-- 采样器的 proto.json：每条 conntrack 流在首包阶段被打上协议标签，
-- 之后即使被 HNAT/PPE 接管，字节仍按这个标签累计。
function api_proto_traffic(mac)
	local target = mac_arg(mac)
	if not traffic then json_out({ order = {}, list = {}, lan = {} }); return end
	local ok, d = pcall(traffic.proto_traffic, target)
	if not ok or type(d) ~= "table" then
		json_out({ order = {}, list = {}, lan = {} })
		return
	end
	json_out(d)
end

-- 采样器状态：给页面页脚/排障用，也方便确认特征库是否真的加载了。
function api_sampler_info()
	if not traffic then json_out({}); return end
	local ok, d = pcall(traffic.feature_info)
	if not ok or type(d) ~= "table" then json_out({}); return end
	json_out(d)
end
