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
-- Section 1: 全部配置扁平存放在 'global' section (与 init 脚本 / p2ptap.config 一致)
---------------------------------------------------------------------
s = m:section(NamedSection, "global", "p2ptap", translate("基础与网络配置"))
s.addremove = false
s:tab("basic",    translate("基本配置"))
s:tab("network",  translate("虚拟网卡与IP拓扑"))
s:tab("peers",    translate("节点与监听配置"))
s:tab("subnet",   translate("内网子网路由 (Site-to-Site)"))
s:tab("transport",translate("传输协议"))
s:tab("obfs",     translate("流量混淆与加密"))
s:tab("exit",     translate("出口网关"))
s:tab("acl",      translate("访问控制 (ACL)"))
s:tab("webui",    translate("WebUI 控制台"))

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

o = s:taboption("basic", Flag, "discover_boot_mesh", translate("自动发现 Boot 骨干集群 (Discover Boot Mesh)"))
o.default = "1"
o.description = translate("自动发现并接入由多个 p2ptap-boot 互联构成的骨干网中继集群，实现跨区域节点全自动互通。")

o = s:taboption("basic", Value, "node_key_file", translate("身份私钥文件路径 (Node Key File)"))
o.datatype = "string"
o.default = "/etc/p2ptap/node.key"
o.placeholder = "/etc/p2ptap/node.key"

o = s:taboption("basic", ListValue, "transport_strategy", translate("传输多径策略 (Transport Strategy)"))
o:value("best_path", translate("最优路径 (Best Path - 低延迟自动优选)"))
o:value("multipath", translate("多径调度 (Multipath - 跨路径重排/抗丢包)"))
o:value("redundant", translate("多径双发 (Redundant - 极速双发抗丢包)"))
o:value("fallback",  translate("自动退避 (Fallback - 稳定保底)"))
o.default = "best_path"
o.description = translate("multipath 下接收端开启重排缓冲，可结合 rx_reorder_window / rx_reorder_delay_ms 调优。")

o = s:taboption("basic", Value, "stats_sample_every", translate("统计采样率 (Stats Sample Every)"))
o.datatype = "range(1, 1000000)"
o.default = "1"
o.description = translate("每 N 帧记录一次报文分类统计。1 = 全量记录 (默认)。高吞吐部署可提升至 16-64 降低 CPU。字节/包速率统计始终精确。")

o = s:taboption("basic", Flag, "force_private_reachability", translate("强制私有可达性 (Force Private Reachability)"))
o.default = "0"
o.description = translate("强制 libp2p 主机宣告为私有 (仅中继可达)。默认关闭: 通过 AutoNAT 自动检测，公网节点仍宣告直连地址。仅当 AutoNAT 在您的网络中不可靠时启用。")

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
o.datatype = "cidr6"

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
o.default = "auto"
o.description = translate("OpenWrt 使用 auto 或 tap。")

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

-- Tab: subnet (内网网段宣告与互联)
o = s:taboption("subnet", DynamicList, "advertised_subnets", translate("宣告本地内网网段 (Advertised Subnets)"))
o.placeholder = "192.168.1.0/24"
o.description = translate("将当前路由器下挂的局域网网段宣告给 P2P 虚拟网中的对端，使对端设备无需安装客户端即可直接访问本内网主机。")

o = s:taboption("subnet", Flag, "accept_advertised_subnets", translate("自动接收并接入对端宣告的子网路由"))
o.default = "0"
o.description = translate("启用后，路由器将自动在系统路由表中添加对端节点宣告的内网网段路由，实现 Site-to-Site 双向无缝互通。")

o = s:taboption("subnet", DynamicList, "allowed_subnet_peers", translate("允许接入子网的 Peer ID 白名单"))
o.placeholder = "*"
o.default = "*"
o.description = translate("填写允许向本机推送子网路由的 Peer ID 列表。填写 '*' 表示信任并允许所有合法节点。")
o:depends("accept_advertised_subnets", "1")

-- Tab: transport
o = s:taboption("transport", Flag, "enable_quic_reuse", translate("启用 QUIC v1 传输协议"))
o.default = "1"

o = s:taboption("transport", Flag, "enable_webrtc", translate("启用 WebRTC Direct 穿透协议"))
o.default = "1"
o.description = translate("基于浏览器/原生 WebRTC 的 NAT 穿透传输层。")

o = s:taboption("transport", Flag, "enable_webrtc_signaling", translate("启用 WebRTC 信令穿透 (WebRTC Signaling)"))
o.default = "1"
o.description = translate("中继专用对端无法直连时，通过控制通道交换真实 SDP 并运行完整 ICE (STUN/TURN)，可穿越一层或两层 NAT。独立于 webrtc-direct (LITE 无法穿 NAT)。需重启生效。")

o = s:taboption("transport", Flag, "enable_webtransport", translate("启用 WebTransport 协议"))
o.default = "1"
o.description = translate("基于 HTTP/3 QUIC 的新型传输协议。")

o = s:taboption("transport", Flag, "enable_tcp_reuse", translate("启用 TCP 复用协议"))
o.default = "1"

o = s:taboption("transport", Value, "tls_server_name", translate("TLS SNI 服务器名 (TLS Server Name)"))
o.placeholder = "留空表示不发送 SNI"
o.description = translate("出站握手 (TLS-over-TCP 与 QUIC) 的 server_name (SNI)。设置后使网格流量更接近普通 HTTP/3。不影响认证。")

o = s:taboption("transport", Value, "tls_sni_suffix", translate("按 Peer 派生 SNI 后缀 (TLS SNI Suffix)"))
o.placeholder = "例如 vpn.example.com"
o.description = translate("出站 SNI 变为 '<peer 标签>.<后缀>'，使每个链路呈现稳定且不同的 SNI，避免所有节点发送相同 SNI 的全局关联特征。优先于 tls_server_name。需重启生效。")

o = s:taboption("transport", Flag, "disable_circuit_relay", translate("禁用 Circuit Relay 标准中继"))
o.default = "0"
o.description = translate("仅关闭 libp2p circuit-relay 与 AutoRelay，保留 DCUtR 打洞。")

o = s:taboption("transport", Flag, "disable_hole_punching", translate("禁用 DCUtR 打洞"))
o.default = "0"
o.description = translate("仅关闭 DCUtR 打洞，保留 Circuit Relay 与 AutoRelay。")

o = s:taboption("transport", Flag, "disable_relay", translate("禁用全部中继与打洞 (诊断)"))
o.default = "0"
o.description = translate("一次性关闭 Circuit Relay + AutoRelay + DCUtR，仅依赖直连或 p2ptap 专有骨干中继。不影响 p2ptap 自身 overlay 中继。")

o = s:taboption("transport", Flag, "relay_header_multihash", translate("overlay 中继帧使用 multihash 头"))
o.default = "0"
o.description = translate("以紧凑 0x03 头发送 p2ptap overlay 中继帧 (Peer ID 用原始 multihash 而非 base58 CID)。默认关闭: 仅当整个传输路径上所有 overlay 中继与 boot 中继都已升级时启用，否则中间 v2 节点会丢弃帧。读取端始终兼容两种头。")

o = s:taboption("transport", DynamicList, "stun_servers", translate("STUN 服务器 (WebRTC ICE)"))
o.placeholder = "/udp/stun.l.google.com/19302"
o.description = translate("WebRTC ICE 候选收集的 STUN 服务器 Multiaddr。提供 server-reflexive 候选，显著提升 WebRTC 打洞成功率。留空则仅依赖 host 候选。")

o = s:taboption("transport", DynamicList, "turn_servers", translate("TURN 服务器 (WebRTC 中继回退)"))
o.placeholder = "turn:host:port?username=user&credential=pass"
o.description = translate("TURN 中继回退 URL。必须携带凭据，否则 WebRTC 会整体中止。留空为正确默认: 走 STUN + 打洞，TURN 仅作回退。")

o = s:taboption("transport", Value, "rx_reorder_window", translate("接收端重排缓冲 (Rx Reorder Window)"))
o.datatype = "range(1, 1024)"
o.default = "1024"
o.description = translate("multipath 策略下的接收端重排缓冲帧数上限。匹配去重容忍度 (1024)。")
o:depends("transport_strategy", "multipath")

o = s:taboption("transport", Value, "rx_reorder_delay_ms", translate("重排队头超时 (Rx Reorder Delay, ms)"))
o.datatype = "range(1, 5000)"
o.default = "300"
o.description = translate("multipath 下队头阻塞的强制释放超时毫秒数。默认 300ms 覆盖 LAN+WAN 直连路径的延迟差；混合 RTT 差更大的路径可调高。")
o:depends("transport_strategy", "multipath")

-- Tab: obfs (流量混淆与加密) — 与 daemon ObfuscationConfig 对齐
o = s:taboption("obfs", Flag, "obfuscation_enable", translate("启用二层数据包流量混淆"))
o.default = "1"

o = s:taboption("obfs", ListValue, "obfuscation_algorithm", translate("载荷加密算法 (Algorithm)"))
o:value("auto",     translate("自动协商 (Auto - 首选 ChaCha20-Poly1305)"))
o:value("chacha20", translate("ChaCha20-Poly1305 (ARM/无 AES 硬件加速路由器推荐)"))
o:value("aes-gcm",  translate("AES-128-GCM (x86_64 / 带 AES-NI 路由器推荐)"))
o:value("none",     translate("明文 (None - 关闭加密，仅保留帧混淆)"))
o.default = "auto"
o:depends("obfuscation_enable", "1")

o = s:taboption("obfs", DynamicList, "padding_rules", translate("填充规则 (Padding Rules)"))
o.placeholder = "0 -> 400-600"
o.description = translate("每行一条填充带规则，语法: '<floor> -> <target_min>[-<target_max>]'。可选一行 'coalesce on|off [max_delay_ms=N] [max_bytes=N] [max_frames=N]' 控制包聚合。留空使用默认规则 '0 -> 400-600' (小于 400 字节填充到 400-600 随机长度，400 以上原样发送，并启用聚合)。带区间按 floor 升序。")
o:depends("obfuscation_enable", "1")

o = s:taboption("obfs", Value, "max_frag_size", translate("分片上限 (Max Frag Size)"))
o.datatype = "range(0, 1400)"
o.default = "0"
o.description = translate("TAP 帧分片层的单分片内层大小上限 (字节)。0 = 由节点根据 MTU 与混淆开销自动推导。范围 256-1400。")
o:depends("obfuscation_enable", "1")

o = s:taboption("obfs", Flag, "strict_key_negotiation", translate("严格密钥协商 (Strict Key Negotiation)"))
o.default = "1"
o.description = translate("强制每对 Peer 用一次性 ECDH(P256) 临时密钥派生独立密钥 (前向保密)。关闭则允许在重同步时退回到长寿命节点密钥。")
o:depends("obfuscation_enable", "1")

o = s:taboption("obfs", Flag, "require_auth_key_exchange", translate("强制认证密钥交换 (Require Auth Key Exchange)"))
o.default = "1"
o.description = translate("对每个 Peer 强制身份签名的密钥交换，防止中继跳替换密钥的降级攻击。开启后与未升级的旧节点不建立加密连接；仅在全部节点均已升级的舰队上启用。")
o:depends("obfuscation_enable", "1")

-- Tab: exit
o = s:taboption("exit", Flag, "exit_enable", translate("启用出口网关模式 (Enable Exit Node)"))
o.default = "0"
o.description = translate("启用后本节点允许对端节点通过本机访问外部网络。相当于 P2P VPN 网关。")

o = s:taboption("exit", Flag, "nat_masquerade", translate("启用 NAT 伪装 (NAT Masquerade)"))
o.default = "0"
o.description = translate("为转发的出站流量自动添加 SNAT 规则 (iptables MASQUERADE)。")
o:depends("exit_enable", "1")

o = s:taboption("exit", Value, "wan_interface", translate("出口物理网卡 (WAN Interface)"))
o.placeholder = "auto"
o.default = "auto"
o.description = translate("提供外部网络出口的物理网卡名称，如 eth0 / wan / pppoe-wan。填写 'auto' 自动检测默认路由网卡。")
o:depends("exit_enable", "1")

-- Tab: acl (访问控制) — 与 daemon ACLConfig 对齐
o = s:taboption("acl", Flag, "acl_enable", translate("启用访问控制 (Enable ACL)"))
o.default = "0"
o.description = translate("启用后按默认动作 + 规则列表过滤网格流量。默认关闭 (网格完全开放)。")

o = s:taboption("acl", ListValue, "acl_default_action", translate("默认动作 (Default Action)"))
o:value("allow", translate("允许 (Allow)"))
o:value("deny",  translate("拒绝 (Deny)"))
o.default = "allow"
o:depends("acl_enable", "1")

o = s:taboption("acl", DummyValue, "_acl_rules_note", translate("详细 ACL 规则"))
o.description = translate("细粒度规则 (每条的 rule_id / action / direction / peer_id / ip_cidr / protocol / port / comment) 请通过配置文件手动编辑: /etc/config/p2ptap 或生成的 /tmp/etc/p2ptap.json 的 acl.rules 数组。")
o:depends("acl_enable", "1")

-- Tab: webui
o = s:taboption("webui", Flag, "webui_enable", translate("启用内置 WebUI Dashboard"))
o.default = "1"

o = s:taboption("webui", Value, "webui_listen_ip", translate("WebUI 监听 IPv4 地址"))
o.datatype = "ip4addr"
o.default = "0.0.0.0"
o.description = translate("WebUI Dashboard 绑定的 IPv4 监听地址，0.0.0.0 表示监听所有接口。")

o = s:taboption("webui", Value, "webui_listen_ipv6", translate("WebUI 监听 IPv6 地址"))
o.datatype = "ip6addr"
o.placeholder = "::"
o.default = "::"
o.description = translate("WebUI Dashboard 绑定的 IPv6 监听地址，:: 表示监听所有接口。")

o = s:taboption("webui", Value, "webui_port", translate("WebUI 监听端口 (Port)"))
o.datatype = "port"
o.default = "5857"

o = s:taboption("webui", Value, "webui_auth_token", translate("WebUI 访问 Token / 密码"))
o.password = true
o.placeholder = "留空将自动生成随机 Token"
o.description = translate("访问 WebUI 面板所需的认证密钥。如留空，程序启动时将在日志中打印生成的临时 Token。")

o = s:taboption("webui", Value, "pcap_sample_every", translate("抓包采样率 (Pcap Sample Every)"))
o.datatype = "range(1, 1000000)"
o.default = "1"
o.description = translate("实时抓包视图每 N 帧采样 1 帧。1 = 全量。值越大 CPU 越低但抓包越粗。")

o = s:taboption("webui", Value, "pcap_max_rate_per_sec", translate("抓包速率上限 (Pcap Max Rate, 帧/秒)"))
o.datatype = "range(0, 1000000)"
o.default = "0"
o.description = translate("限制每秒捕获的帧数 (0 = 不限)。作为 PcapSampleEvery 之上的二级安全网。")

function m.on_after_commit(self)
	luci.sys.call("/etc/init.d/p2ptap restart >/dev/null 2>&1 &")
end

return m

