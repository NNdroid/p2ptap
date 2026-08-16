module("luci.controller.p2ptap", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/p2ptap") then
		return
	end

	entry({"admin", "services", "p2ptap"}, cbi("p2ptap"), _("p2ptap"), 60).dependent = true
	entry({"admin", "services", "p2ptap", "status"}, call("action_status")).leaf = true
end

function action_status()
	local sys = require "luci.sys"
	local status = {
		running = (sys.call("pidof p2ptap >/dev/null") == 0)
	}
	luci.http.prepare_content("application/json")
	luci.http.write_json(status)
end
