module("luci.controller.p2ptap", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/p2ptap") then
		return
	end

	entry({"admin", "services", "p2ptap"}, cbi("p2ptap"), _("p2ptap"), 60).dependent = true
	entry({"admin", "services", "p2ptap", "status"}, call("action_status")).leaf = true
end

local function format_speed(bps)
	bps = tonumber(bps) or 0
	if bps <= 0 then return "0 B/s" end
	if bps < 1024 then
		return string.format("%d B/s", bps)
	elseif bps < 1024 * 1024 then
		return string.format("%.1f KB/s", bps / 1024)
	else
		return string.format("%.2f MB/s", bps / (1024 * 1024))
	end
end

local function read_file_trim(path)
	local f = io.open(path, "r")
	if not f then return nil end
	local content = f:read("*l")
	f:close()
	if content then
		content = content:gsub("^%s+", ""):gsub("%s+$", "")
		if #content > 0 then return content end
	end
	return nil
end

function action_status()
	local sys = require "luci.sys"
	local shellquote = require("luci.util").shellquote
	local uci = require("luci.model.uci").cursor()
	local json = require "luci.jsonc"

	local is_running = (sys.call("pidof p2ptap >/dev/null") == 0)
	local status = {
		running = is_running,
		stats_available = false,
		peer_id = "",
		node_name = "",
		tap_ip = "",
		tap_ipv6 = "",
		tap_mac = "",
		peer_count = 0,
		tx_speed = "0 B/s",
		rx_speed = "0 B/s",
		active_exit = "",
		webui_url = "",
		peers = {}
	}

	if is_running then
		local port = tonumber(uci:get("p2ptap", "global", "webui_port")) or 5857
		if port < 1 or port > 65535 or port % 1 ~= 0 then port = 5857 end
		local web_enabled = uci:get("p2ptap", "global", "webui_enable") ~= "0"
		if not web_enabled then
			luci.http.prepare_content("application/json")
			luci.http.write_json(status)
			return
		end
		local auth_token = uci:get("p2ptap", "global", "webui_auth_token") or ""

		-- Search for sidecar token file written by daemon
		local token_paths = {
			"/tmp/etc/.p2ptap_webui_token",
			"/tmp/etc/.p2ptap_token",
			"/var/etc/p2ptap/.p2ptap_webui_token",
			"/etc/p2ptap/.p2ptap_webui_token",
			"/tmp/.p2ptap_webui_token"
		}
		for _, tp in ipairs(token_paths) do
			local t = read_file_trim(tp)
			if t and #t > 0 then
				auth_token = t
				break
			end
		end


		-- Use query parameter ?token=... for 100% compatibility with busybox wget, uclient-fetch, and curl
		local token_param = ""
		if auth_token and #auth_token > 0 then
			token_param = "?token=" .. luci.http.urlencode(auth_token)
		end

		local listen_ip = uci:get("p2ptap", "global", "webui_listen_ip") or "0.0.0.0"
		local listen_ipv6 = uci:get("p2ptap", "global", "webui_listen_ipv6") or "::"
		local api_host = listen_ip == "0.0.0.0" and "127.0.0.1" or listen_ip
		if api_host == "" then
			api_host = "[" .. (listen_ipv6 == "::" and "::1" or listen_ipv6) .. "]"
		end
		local url = string.format("http://%s:%s/api/stats%s", api_host, port, token_param)

		-- Try multiple fetchers with generous 3s timeout to avoid intermittent dropouts on router load
		local cmd = string.format(
			"uclient-fetch -q -O - -T 3 %s 2>/dev/null " ..
			"|| wget -q -O - -T 3 %s 2>/dev/null " ..
			"|| curl -fsS -m 3 --connect-timeout 2 %s 2>/dev/null",
			shellquote(url), shellquote(url), shellquote(url)
		)

		local raw_json = sys.exec(cmd)
		if raw_json and #raw_json > 0 then
			local data = json.parse(raw_json)
			if type(data) == "table" and type(data.peer_id) == "string" then
				status.stats_available = true
				status.peer_id = data.peer_id or ""
				status.node_name = data.node_name or ""
				status.tap_ip = data.tap_ip or ""
				status.tap_ipv6 = data.tap_ipv6 or ""
				status.tap_mac = data.mac or ""
				if data.active_peers then
					status.peer_count = #data.active_peers
					status.peers = data.active_peers
				end
				if data.speed then
					status.tx_speed = format_speed(data.speed.tx_bytes_per_sec)
					status.rx_speed = format_speed(data.speed.rx_bytes_per_sec)
				end
				if data.exit_node and data.exit_node.active_exit_tap_ip and #data.exit_node.active_exit_tap_ip > 0 then
					status.active_exit = data.exit_node.active_exit_tap_ip
				end
			end
		end

		-- Resolve WebUI URL (read sidecar or fallback to router host IP)
		local url_paths = {
			"/tmp/etc/.p2ptap_webui_url",
			"/var/etc/p2ptap/.p2ptap_webui_url",
			"/etc/p2ptap/.p2ptap_webui_url",
			"/tmp/.p2ptap_webui_url"
		}
		for _, up in ipairs(url_paths) do
			local u = read_file_trim(up)
			if u and #u > 0 then
				status.webui_url = u
				break
			end
		end

		-- The browser substitutes wildcard/loopback addresses with its hostname.
		if status.webui_url == "" then
			status.webui_url = string.format("http://0.0.0.0:%s/", port)
		end

		-- Attach token to WebUI URL for seamless single-click login
		if auth_token and #auth_token > 0 and not status.webui_url:find("token=") then
			status.webui_url = status.webui_url .. (status.webui_url:find("%?") and "&token=" or "?token=") .. luci.http.urlencode(auth_token)
		end
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(status)
end

