local m, s, o

m = Map("p2ptap", translate("p2ptap 控制台"),
	translate("基于 go-libp2p 的二层 P2P TAP 点对点虚拟局域网。支持全功能参数配置、网络传输调优、流量混淆、出口网关模式、一键服务控制及内置 WebUI 管理入口。"))

---------------------------------------------------------------------
-- Section 0: 运行状态
---------------------------------------------------------------------
s = m:section(TypedSection, "p2ptap", translate("运行状态"))
s.anonymous = true
o = s:option(DummyValue, "_status", translate("服务运行状态"))
o.template = "p2ptap/status"

---------------------------------------------------------------------
-- Section 1: 基础与网络配置 (对应 config p2ptap 'global')
---------------------------------------------------------------------
s = m:section(NamedSection, "global", "p2ptap", translate("基础与网络配置"))
s.addremove = false
s:tab("basic",  translate("基本配置"))
s:tab("network", translate("虚拟网卡与IP拓扑"))
s:tab("peers",   translate("节点与监听配置"))

-- Tab: basic
o = s:taboption("basic", Flag, "enabled", translate("启用 p2ptap 服务"))
o.rmempty = false

o = s:taboption("basic", Value, "node_name", translate("节点名称 (Node Name)"))
o.datatype = "string"
o.placeholder = "openwrt-router"
o.description = translate("网络中标识本路由器的名称，留空默认使用系统 Hostname。")

o = s:taboption("basic", ListValue, "log_level", translate("日志记录级别 (Log Level)"))
o:value("debug", translate("调试 (Debug)"))
o:value("info",  translate("信息 (Info)"))
o:value("warn",  translate("警告 (Warn)"))
o:value("error", translate("错误 (Error)"))
o.default = "info"

o = s:taboption("basic", Value, "psk", translate("预共享密钥 (PSK)"))
o.password = true
o.placeholder = "64 位 Hex 字符串，留空仅限 LAN/mDNS 组网"
o.description = translate("设置 64 位 Hex 秘钥形成私有隔离加密网络。只与相同 PSK 的节点组网。留空则仅通过 mDNS + Static Peers 发现节点。")
function o.validate(self, value, section)
	if value and #value > 0 then
		if #value ~= 64 or not value:match("^[0-9a-fA-F]+$") then
			return nil, translate("PSK 必须为 64 位的十六进制(Hex)字符序列！")
		end
	end
	return value
end

o = s:taboption("basic", Value, "node_key_file", translate("身份私钥文件路径 (Node Key File)"))
o.datatype = "string"
o.default = "/etc/p2ptap/node.key"
o.placeholder = "/etc/p2ptap/node.key"

o = s:taboption("basic", ListValue, "transport_strategy", translate("传输多径策略 (Transport Strategy)"))
o:value("best_path", translate("最优路径 (Best Path - 低延迟自动优选)"))
o:value("redundant", translate("多径双发 (Redundant - 极速双发抗丢包)"))
o:value("fallback",  translate("自动退避 (Fallback - 稳定保底)"))
o.default = "best_path"

-- Tab: network
o = s:taboption("network", Value, "tap_name", translate("TAP 虚拟网卡名称"))
o.datatype = "string"
o.default = "p2ptap0"

o = s:taboption("network", Value, "tap_ip", translate("虚拟 IPv4 地址/掩码 (TAP IPv4 CIDR)"))
o.datatype = "cidr4"
o.placeholder = "10.0.0.1/24"
o.description = translate("例如 10.0.0.1/24。同局域网各节点 IP 地址必须在同一网段且保持唯一。")

o = s:taboption("network", Value, "tap_ipv6", translate("虚拟 IPv6 地址/前缀 (TAP IPv6 CIDR)"))
o.placeholder = "fd00::1/64"
o.description = translate("例如 fd00::1/64。提供原生二层 IPv6 组网能力。")
function o.validate(self, value, section)
	if value and #value > 0 then
		if not value:match("^[%x:]+/%d+$") then
			return nil, translate("IPv6 地址格式错误！必须为带前缀格式 (如 fd00::1/64)")
		end
	end
	return value
end

o = s:taboption("network", Value, "tap_mac", translate("TAP 网卡 MAC 地址 (TAP MAC)"))
o.datatype = "macaddr"
o.placeholder = "留空将自动随机生成"
o.description = translate("虚拟网卡的二层 MAC 地址。如留空将自动随机生成并持久化。")

o = s:taboption("network", Value, "mtu", translate("接口最大传输单元 (MTU)"))
o.datatype = "range(68, 9000)"
o.default = "1500"
o.description = translate("推荐默认 1500 (范围: 68-9000)。")

o = s:taboption("network", Flag, "enable_mdns", translate("启用 mDNS 局域网节点发现"))
o.default = "1"
o.description = translate("本地局域网内自动发现其他 P2P 节点。")

o = s:taboption("network", ListValue, "driver_type", translate("TAP 驱动类型 (Driver Type)"))
o:value("auto",   translate("自动检测 (Auto)"))
o:value("tap",    translate("TAP 驱动 (Linux/macOS)"))
o:value("wintun", translate("WinTun 驱动 (Windows)"))
o.default = "auto"
o.description = translate("Windows 系统推荐 wintun，其他系统使用 auto 即可。")

-- Tab: peers
o = s:taboption("peers", DynamicList, "bootstrap_peers", translate("引导节点列表 (Bootstrap Peers)"))
o.placeholder = "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTmoXMY5PeBKyy1EicV2g7HQ1b18423b"
o.description = translate("公共或私有的 P2P 引导节点 Multiaddr 列表。多行输入，每行一条。")

o = s:taboption("peers", DynamicList, "static_peers", translate("静态直连节点 (Static Peers)"))
o.placeholder = "/ip4/x.x.x.x/udp/4001/quic-v1/p2p/12D3KooW..."
o.description = translate("手动指定直连对端节点的 Multiaddr。")

o = s:taboption("peers", DynamicList, "listen_addrs", translate("本地 P2P 监听地址 (Listen Multiaddrs)"))
o.placeholder = "/ip4/0.0.0.0/udp/4001/quic-v1"
o.description = translate("本地监听的多地址 Multiaddr 列表。支持 QUIC/WebRTC/WebTransport/TCP。")

---------------------------------------------------------------------
-- Section 2: 传输协议 (对应 config transports 'transports')
---------------------------------------------------------------------
s = m:section(NamedSection, "transports", "transports", translate("传输协议高级设置"))
s.addremove = false

o = s:option(Flag, "enable_quic_reuse", translate("启用 QUIC v1 传输协议"))
o.default = "1"

o = s:option(Flag, "enable_webrtc", translate("启用 WebRTC Direct 穿透协议"))
o.default = "1"
o.description = translate("基于浏览器/原生 WebRTC 的 NAT 穿透传输层。")

o = s:option(Flag, "enable_webtransport", translate("启用 WebTransport 协议"))
o.default = "1"
o.description = translate("基于 HTTP/3 QUIC 的新型传输协议。")

o = s:option(Flag, "enable_tcp_reuse", translate("启用 TCP 复用协议"))
o.default = "1"

o = s:option(Flag, "enable_tcp_brutal", translate("启用 TCP Brutal 拥塞控制"))
o.default = "0"
o.description = translate("高吞吐场景的激进 TCP 拥塞算法。需内核支持。")

o = s:option(Value, "tcp_brutal_rate", translate("TCP Brutal 速率上限"))
o.placeholder = "100Mbps"
o.description = translate("例如 100Mbps / 1Gbps。启用 TCP Brutal 后生效。")
o:depends("enable_tcp_brutal", "1")

---------------------------------------------------------------------
-- Section 3: 流量混淆 (对应 config obfuscation 'obfuscation')
---------------------------------------------------------------------
s = m:section(NamedSection, "obfuscation", "obfuscation", translate("流量混淆与数据填充"))
s.addremove = false

o = s:option(Flag, "enable", translate("启用二层数据包流量混淆"))
o.default = "1"

o = s:option(ListValue, "mode", translate("混淆填充模式 (Mode)"))
o:value("fixed",  translate("固定对齐 (Fixed Padding)"))
o:value("block",  translate("分块对齐 (Block Padding)"))
o:value("random", translate("随机填充 (Random Padding)"))
o:value("dynamic", translate("动态自适应 (Dynamic)"))
o:value("auto",   translate("全自动 (Auto - 智能检测)"))
o.default = "fixed"
o:depends("enable", "1")

o = s:option(Value, "fixed_size", translate("固定填充包长 (Fixed Size)"))
o.datatype = "range(64, 9000)"
o.default = "1500"
o.description = translate("所有数据包对齐到的目标字节长度。仅 fixed 模式。")
o:depends("mode", "fixed")

o = s:option(Value, "block_size", translate("分块填充对齐粒度 (Block Size)"))
o.datatype = "range(16, 1024)"
o.default = "256"
o.description = translate("数据包按此字节数向上对齐。仅 block 模式。")
o:depends("mode", "block")

o = s:option(Value, "jitter_range", translate("随机抖动范围 (Jitter Range, ±N bytes)"))
o.datatype = "range(0, 512)"
o.default = "0"
o.description = translate("在填充基础上附加 ±N 字节随机抖动。0 = 关闭抖动。")
o:depends("enable", "1")

o = s:option(Value, "min_size", translate("最小帧尺寸 (Min Size)"))
o.datatype = "range(64, 2000)"
o.default = "128"
o.description = translate("dynamic 模式下的最小帧尺寸。")
o:depends("mode", "dynamic")

o = s:option(Value, "max_size", translate("最大帧尺寸 (Max Size)"))
o.datatype = "range(256, 9000)"
o.default = "1500"
o.description = translate("dynamic 模式下的最大帧尺寸。")
o:depends("mode", "dynamic")
o:depends("mode", "auto")

o = s:option(Value, "auto_detect_interval", translate("自动检测间隔 (Auto Detect Interval, 秒)"))
o.datatype = "range(5, 600)"
o.default = "30"
o.description = translate("Auto 模式下重新评估混淆策略的间隔秒数。")
o:depends("mode", "auto")

o = s:option(Value, "auto_threshold_bytes", translate("自动切换阈值 (Auto Threshold Bytes)"))
o.datatype = "range(1024, 1073741824)"
o.default = "1048576"
o.description = translate("Auto 模式下累计传输超过此字节数后触发重评估。默认 1MB。")
o:depends("mode", "auto")

o = s:option(Flag, "allow_mode_switch", translate("允许自动切换模式 (Allow Mode Switch)"))
o.default = "0"
o.description = translate("Auto 模式下允许引擎自动切换混淆策略。启用后可能产生短暂抖动。")
o:depends("mode", "auto")

---------------------------------------------------------------------
-- Section 4: 出口网关 (对应 config exit_node 'exit_node')
---------------------------------------------------------------------
s = m:section(NamedSection, "exit_node", "exit_node", translate("出口网关 (Exit Node)"))
s.addremove = false

o = s:option(Flag, "enable", translate("启用出口网关模式 (Enable Exit Node)"))
o.default = "0"
o.description = translate("启用后本节点允许对端节点通过本机访问外部网络。相当于 P2P VPN 网关。")

o = s:option(Flag, "nat_masquerade", translate("启用 NAT 伪装 (NAT Masquerade)"))
o.default = "0"
o.description = translate("为转发的出站流量自动添加 SNAT 规则 (iptables MASQUERADE)。")
o:depends("enable", "1")

o = s:option(Value, "wan_interface", translate("出口物理网卡 (WAN Interface)"))
o.placeholder = "auto"
o.default = "auto"
o.description = translate("提供外部网络出口的物理网卡名称，如 eth0 / wan / pppoe-wan。填写 'auto' 自动检测默认路由网卡。")
o:depends("enable", "1")

---------------------------------------------------------------------
-- Section 5: WebUI 控制台 (对应 config webui 'webui')
---------------------------------------------------------------------
s = m:section(NamedSection, "webui", "webui", translate("WebUI 控制台"))
s.addremove = false

o = s:option(Flag, "enable", translate("启用内置 WebUI Dashboard"))
o.default = "1"

o = s:option(Value, "listen_ip", translate("WebUI 监听 IPv4 地址"))
o.datatype = "ip4addr"
o.default = "0.0.0.0"
o.description = translate("WebUI Dashboard 绑定的 IPv4 监听地址，0.0.0.0 表示监听所有接口。")

o = s:option(Value, "listen_ipv6", translate("WebUI 监听 IPv6 地址"))
o.placeholder = "::"
o.default = "::"
o.description = translate("WebUI Dashboard 绑定的 IPv6 监听地址，:: 表示监听所有接口。")

o = s:option(Value, "port", translate("WebUI 监听端口 (Port)"))
o.datatype = "port"
o.default = "5857"

o = s:option(DummyValue, "_webui_link", translate("控制台快捷入口"))
o.rawhtml = true
function o.cfgvalue(self, section)
	local port = m.uci:get("p2ptap", "webui", "port") or "5857"
	local lip = m.uci:get("p2ptap", "webui", "listen_ip") or "0.0.0.0"
	local display_ip = lip
	if lip == "0.0.0.0" then
		local host = luci.http.getenv("HTTP_HOST") or ""
		display_ip = host:match("^([^:]+)") or "127.0.0.1"
	end
	local url = "http://" .. display_ip .. ":" .. port
	return '<div style="margin:12px 0;"><a href="' .. url .. '" target="_blank" class="cbi-button cbi-button-apply" style="background:linear-gradient(135deg, #06b6d4, #3b82f6); color:#fff; border:none; padding:10px 24px; border-radius:8px; font-weight:bold; font-size:15px; text-decoration:none; display:inline-block; box-shadow:0 4px 12px rgba(6,182,212,0.3);">🚀 打开 p2ptap 高级 WebUI 控制台 (' .. url .. ')</a></div>'
end

return m
