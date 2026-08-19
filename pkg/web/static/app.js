/* p2ptap WebUI — application logic (extracted from index.html) */

/* ── Strict-separation event delegation ──
 * index.html declares behavior via declarative data-on<event>="<expr>"
 * attributes instead of inline on<event> handlers. This single delegate
 * executes each expression in the element's context, so `this` and the
 * global `event` behave exactly as a real inline handler would. All other
 * document-level listeners remain untouched. */
(function installDataOnDelegation() {
    var EVENTS = ['click', 'change', 'input', 'submit', 'contextmenu',
                  'mouseover', 'mouseout', 'focus', 'blur'];
    EVENTS.forEach(function (evt) {
        var attr = 'data-on' + evt;
        document.addEventListener(evt, function (e) {
            var el = e.target;
            // Walk up to the element that carries the handler attribute.
            while (el && el !== document && !(el.hasAttribute && el.hasAttribute(attr))) {
                el = el.parentNode;
            }
            if (!el || el === document || !el.hasAttribute(attr)) return;
            var code = el.getAttribute(attr);
            if (!code) return;
            try {
                // `this` is bound to the element; bare identifiers (e.g.
                // closeConfigModal) resolve against the global scope.
                new Function('e', code).call(el, e);
            } catch (err) {
                console.error('[data-on' + evt + '] failed:', code, err);
            }
        });
    });
})();

        let latestStatsData = null;
        let latestTopologyData = null; // full mesh topology from /api/topology (SPT hierarchy)
        const i18nDict = {
            en: {
                default_node_name: "P2P TAP VPN Node",
                login_title: "🔐 P2P TAP Dashboard Login",
                login_subtitle: "This dashboard is protected. Enter your access token to continue.",
                login_token_label: "Access Token",
                login_token_placeholder: "Paste token from startup log or config (webui.auth_token)",
                login_btn: "Login",
                login_error: "Invalid token or request failed. Please try again.",
                login_hint: "The token is stored locally in your browser and sent as a Bearer header.",
                topology_title: "🗺️ Topology Star Map",
                topology_sub: "(Drag nodes to reposition | Scroll to zoom | Double-click for Ping)",
                reset_view: "🎯 Reset View",
                topo_standalone: "🌐 Standalone Mesh Node (Awaiting P2P Peer Connections...)",
                topo_self_node: "Self Node",
                protocol_inspector_title: "📊 Live Traffic & Ethernet Protocol Inspector",
                protocol_inspector_desc: "(Layer-2/3/4 packet breakdown & live PPS statistics)",
                proto_channels_title: "📡 Protocol Streams & Subsystem Channels",
                th_stream_proto: "Protocol / Channel",
                th_stream_peer: "Remote Peer",
                th_stream_direction: "Direction",
                th_stream_transport: "Transport & Multiaddr",
                th_stream_status: "Status",
                search_streams_ph: "Search streams, protocols, peers…",
                no_matching_streams: "No active protocol streams found",
                no_channels: "No active protocol channels",
                lbl_active_streams: "Streams",
                lbl_streams: "streams",
                dir_out: "Outbound ↑",
                dir_in: "Inbound ↓",
                stream_active: "Active",
                channel_status_active: "Active",
                channel_status_running: "Running",
                channel_status_idle: "Idle",
                channel_status_standby: "Standby",
                channel_status_ready: "Ready",
                channel_status_open: "Open Mode",
                category_sync: "Sync",
                category_routing: "Routing",
                category_pubsub: "PubSub",
                category_data: "Data",
                category_security: "Security",
                category_transport: "Transport",
                category_diagnostics: "Diagnostics",
                category_discovery: "Discovery",
                channel_seqsync_name: "Sequence Sync (SeqSync)",
                channel_seqsync_desc: "Window Dedup & Replay Protection",
                channel_lsa_name: "LSA Mesh Routing",
                channel_lsa_desc: "Dijkstra Shortest Path",
                channel_peekmap_name: "Peek-Map Broadcast",
                channel_peekmap_desc: "Bootstrap Topology Sync",
                channel_data_name: "Virtual TAP Datapath",
                channel_data_proto: "Layer-2 Ethernet Overlay",
                channel_auth_name: "Mesh Authentication",
                channel_auth_desc: "PSK Mesh Network Isolation",
                channel_dcutr_name: "DCUtR Hole-Punch & Relay",
                channel_dcutr_desc: "Direct Connection Upgrade",
                cipher_lbl: "Cipher",

                lbl_arp_broadcast: "ARP Broadcast Frames",
                lbl_broadcast_pkts: "Broadcast Packets",
                lbl_multicast_pkts: "Multicast Packets",
                lbl_gateway_pkts: "Exit Node Gateway Packets",
                desc_broadcast: "L2 Broadcast (incl. ARP)",
                desc_multicast: "L2 Multicast (incl. mDNS)",
                desc_gateway: "Tunnelled via Exit Node",
                lbl_seq_sync: "Seq Sync & Dedup",
                desc_seq_sync: "Synced peers · replay/window drops",
                lbl_icmp_ping: "ICMP Echo (Ping)",
                lbl_udp_packets: "UDP Transport Packets",
                lbl_tcp_packets: "TCP Stream Packets",
                desc_arp: "Layer-2 Address Resolution",
                desc_icmp: "Network Probes & Keepalive",
                desc_udp: "Datagram Transport",
                desc_tcp: "Reliable Byte Streams",
                // ── Topology tooltip labels (node hover) ──
                topo_tt_local_host: "Local Host",
                topo_tt_ipv4: "Virtual IPv4:",
                topo_tt_ipv6: "Virtual IPv6:",
                topo_tt_peer_id: "Peer ID:",
                topo_tt_route: "Route:",
                topo_tt_direct_link: "Direct P2P Link",
                topo_tt_circuit_relay: "Circuit Relay v2",
                topo_tt_optimal_route: "Optimal Route:",
                topo_tt_route_gain: "Route Gain:",
                topo_tt_transit_relay: "Transit Relay",
                topo_tt_seq: "Seq (Tx/Rx):",
                topo_tt_dedup_window: "Dedup Window:",
                topo_tt_dup_drops: "Duplicate Drops:",
                topo_tt_link_integrity: "Link Integrity:",
                topo_tt_blackhole: "Rx blackhole (dedup skew)",
                topo_tt_healthy: "Healthy",
                topo_tt_os_arch: "OS / Arch:",
                topo_tt_tap_ip: "PEER IP:",
                topo_tt_transport: "Transport:",
                topo_tt_rtt: "RTT Latency:",
                topo_tt_live_rate: "Live Rate:",
                topo_tt_uptime: "Uptime:",
                topo_legend_direct_fast: "● Direct (<30ms)",
                topo_legend_direct_slow: "● Direct (30-100ms)",
                topo_legend_relay: "● Transit Relay (amber) — relayed peers hang below",
                topo_legend_flow: "💧 Flow density = real TX/RX rate (idle links don't flow)",
                topo_badge_transit: "🌉 Transit Switch",
                topo_badge_exit_server: "🚪 Exit Server",
                topo_via: "via",
                topo_link_idle: "idle",
                topo_summary_nodes: "Nodes",
                topo_summary_direct: "Direct",
                topo_summary_relayed: "Relayed",
                topo_summary_relays: "Transit Relays",
                topo_summary_thru: "Mesh Thru",
                topo_summary_gw: "Gateway Pkts",
                topo_summary_boots: "Bootstraps",
                topo_summary_static: "Static Peers",
                topo_summary_clusters: "Clusters",
                topo_filter_remote: "Cross-Cluster",
                topo_legend_boot: "● Bootstrap Node (purple)",
                topo_legend_overlay: "◆ Overlay Relay (long dash)",
                topo_badge_boot: "Bootstrap",
                topo_badge_static: "Static",
                topo_tt_role_boot: "Bootstrap Node",
                topo_tt_role_static: "Static Peer",
                topo_tt_cluster: "Cluster:",
                topo_tt_boot_hops: "Boot Hops:",
                topo_tt_transport_path: "Transport Path:",
                topo_tt_relay_hop: "Relay Hop:",
                topo_tt_enc: "Encryption:",
                topo_tt_conn: "Conn State:",
                topo_tt_jitter: "Jitter:",
                topo_tt_loss: "Loss:",
                topo_tt_version: "Version:",
                topo_tt_since: "Connected:",
                topo_tt_geo: "Geo:",
                topo_tt_total: "Total (Tx/Rx):",
                topo_tt_route_via: "Path:",
                modal_add_static_title: "➕ Add Permanent Static Peer Multiaddr",
                modal_add_static_desc: "Enter a full P2P Multiaddr containing target /p2p/<PEER_ID>. Address will be permanently registered in Peerstore with PermanentAddrTTL and auto-connected.",
                lbl_multiaddr_str: "Multiaddr String",
                btn_cancel: "Cancel",
                btn_test_save_peer: "➕ Test & Save Permanent Peer",
                modal_diag_title: "⚡ Peer Path Diagnostics & Benchmark",
                btn_close: "Close",
                btn_add_static_peer: "➕ Add Static Peer",
                pcap_title: "🔬 Packet Capture",
                pcap_stopped: "Stopped",
                pcap_running: "● Capturing",
                pcap_start: "▶️ Start",
                pcap_pause: "⏸️ Pause",
                pcap_clear: "🗑️ Clear",
                pcap_autoscroll: "Auto-scroll",
                pcap_stream_live: "Live stream (WebSocket)",
                pcap_stream_connecting: "Connecting…",
                pcap_stream_polling: "Polling fallback (live stream unavailable)",
                pcap_stream_off: "Stream disconnected",
                pcap_stream_dropped: "frames dropped by slow client",
                log_stream_live: "Live stream (WebSocket)",
                log_stream_connecting: "Connecting…",
                log_stream_polling: "Polling fallback (live stream unavailable)",
                log_stream_off: "Stream disconnected",
                log_stream_dropped: "logs dropped by slow client",
                pcap_desc: "Captures raw Ethernet frames sent/received on the local TAP virtual NIC (incl. src/dst MAC, protocol, IP, hex). <span class=\"tx-tag\">tx</span> = sent by this host, <span class=\"rx-tag\">rx</span> = received. <span class=\"tx-tag\">Click any row</span> to view full details and raw frame hex.",
                pcap_empty: "No data yet. Click \"Start\" to capture local TAP traffic.",
                pcap_click_hint: "Click to view full details",
                pcap_dup_repeat: "Repeated frame — identical to the previous row (mDNS / multicast retransmit)",
                pcap_dup_repeat_row: "Repeated frame — same payload as the row above. This is normal for mDNS / multicast re-emits, not a render duplicate.",
                pcap_modal_title: "🔬 Packet Details",
                pcap_modal_raw: "Full hex (raw frame)",
                pcap_copy_hex: "📋 Copy Hex",
                pcap_dir_tx: "Sent by host (tx)",
                pcap_dir_rx: "Received (rx)",
                pcap_f_seq: "Seq",
                pcap_f_time: "Time",
                pcap_f_dir: "Direction",
                pcap_f_srcmac: "Source MAC",
                pcap_f_dstmac: "Destination MAC",
                pcap_f_etype: "EtherType",
                pcap_f_proto: "Protocol",
                pcap_f_vlan: "VLAN ID",
                pcap_f_l4proto: "L4 Protocol",
                pcap_f_srcip: "Source IP",
                pcap_f_dstip: "Destination IP",
                pcap_f_srcport: "Source Port",
                pcap_f_dstport: "Destination Port",
                pcap_f_tcpflags: "TCP Flags",
                pcap_f_tcpseq: "TCP Sequence",
                pcap_f_tcpwin: "TCP Window",
                pcap_f_dns: "DNS Query",
                pcap_f_sni: "TLS SNI",
                pcap_f_ttl: "TTL",
                pcap_f_arpop: "ARP Op",
                pcap_f_arpsmac: "ARP Sender MAC",
                pcap_f_arpdmac: "ARP Target MAC",
                pcap_f_frompeer: "From Peer",
                pcap_f_topeer: "To Peer",
                pcap_f_len: "Frame Length",
                pcap_f_info: "Protocol Summary",
                pcap_layer_frame: "Frame",
                pcap_layer_tree: "Protocol Dissection",
                pcap_col_seq: "#",
                pcap_col_time: "Time",
                pcap_col_dir: "Dir",
                pcap_col_srcmac: "Src MAC",
                pcap_col_dstmac: "Dst MAC",
                pcap_col_etype: "Type",
                pcap_col_proto: "Proto",
                pcap_col_srcip: "Src IP",
                pcap_col_dstip: "Dst IP",
                pcap_col_ports: "Ports",
                pcap_col_flags: "Flags",
                pcap_col_dns: "DNS",
                pcap_col_sni: "SNI",
                pcap_col_frompeer: "From Peer",
                pcap_col_topeer: "To Peer",
                pcap_col_len: "Len",
                pcap_col_info: "Info",
                pcap_col_hex: "Hex (first 64B)",
                err_enter_multiaddr: "Please enter a valid Multiaddr string",
                toast_testing_adding: "Testing and adding static peer",
                toast_static_added: "Static peer added and permanently registered in Peerstore!",
                toast_add_failed: "Add static peer failed",
                toast_req_err: "Request error",
                speed_test: "⚡ P2P SpeedTest",
                share_config: "📲 Share & Export",
                terminal_title: "📟 Live System Log Stream",
                auto_scroll: "📜 Auto-Scroll: ON",
                auto_scroll_off: "📜 Auto-Scroll: OFF",
                clear_logs: "🗑️ Clear",
                pause_logs: "⏸️ Pause",
                resume_logs: "▶️ Resume",
                log_paused_badge: "⏸ Paused",
                copy_logs: "📋 Copy",
                logs_copied: "📋 Logs copied to clipboard!",
                logs_empty_copy: "Nothing to copy yet.",
                copy_failed: "Copy failed.",
                speedtest_title: "⚡ P2P Link Bandwidth & Latency SpeedTest",
                select_target_peer: "Select Target Peer for SpeedTest",
                mbps_label: "Mbps (P2P Throughput Rate)",
                rtt_avg: "RTT Avg",
                jitter_lbl: "Jitter",
                quality_lbl: "Quality",
                start_test_btn: "🚀 Start Benchmark Test",
                share_title: "📲 Share & Export Configuration",
                share_desc: "Scan QR code or export configuration JSON to deploy nodes.",
                copy_json: "📋 Copy JSON",
                download_json: "💾 Download File",
                col_geo: "Geo Location",
                col_conn_time: "Connected Time",
                col_last_active: "Last Active",
                col_jitter_loss: "Jitter / Loss",
                col_encryption: "Encryption",
                col_status: "Conn Status",
                col_return_path: "Return Path",
                conn_ok: "Connected",
                conn_relay_ok: "Relay OK",
                conn_connecting: "Connecting",
                conn_proto_mismatch: "Proto Mismatch",
                conn_obf_failed: "Decrypt Fail",
                conn_unreachable: "Unreachable",
                return_ok: "Return OK",
                return_dead: "Return Dead",
                return_idle: "Unknown",
                col_actions: "Actions",
                topo_tx: "Outbound (Tx ➔)",
                topo_rx: "Return (Rx ⬅️)",
                topo_relay: "Relayed Hop",
                peer_id_lbl: "PeerID",
                strategy_best_path: "BEST_PATH",
                strategy_low_latency: "LOW_LATENCY",
                strategy_high_bandwidth: "HIGH_BANDWIDTH",
                search_placeholder: "Search…",
                prev_page: "‹ Prev",
                next_page: "Next ›",
                per_page: "Per page",
                no_match: "No match",
                sys_health_title: "💻 System & Runtime Health",
                badge_active: "Active",
                lbl_heap: "Heap Alloc / Sys:",
                lbl_goroutines: "Goroutines:",
                lbl_gc_runs: "GC Runs:",
                lbl_process_uptime: "Process Uptime:",
                lbl_heap_inuse: "Heap In-Use:",
                lbl_heap_objects: "Heap Objects:",
                lbl_stack_inuse: "Stack In-Use:",
                lbl_next_gc: "Next GC @:",
                lbl_last_gc_pause: "Last GC Pause:",
                lbl_gc_cpu: "GC CPU Fraction:",
                lbl_gomaxprocs: "GOMAXPROCS:",
                lbl_cpu_cores: "CPU Cores:",
                security_title: "🛡️ Security & Encryption Status",
                badge_protected: "Protected",
                lbl_psk_status: "PSK Mesh Status:",
                lbl_traffic_obfs: "Traffic Obfuscation:",
                lbl_id_fingerprint: "Identity Fingerprint:",
                lbl_autonat_reach: "AutoNAT Reachability:",
                lbl_per_peer_enc: "Per-Peer Encryption:",
                sec_copy: "Copy",
                sec_copied: "Copied",
                sec_peer_title: "Peer Encryption Details",
                sec_peer_id: "Peer ID",
                sec_peer_algo: "Cipher",
                sec_peer_pfs: "Perfect Forward Secrecy",
                sec_yes: "Yes",
                sec_no: "No",
                sec_peer_tx_fp: "TX Key Fingerprint (SHA-256, first 8 hex)",
                sec_peer_rx_fp: "RX Key Fingerprint (SHA-256, first 8 hex)",
                sec_peer_pfs_eph: "Ephemeral ECDH Public-Key Fingerprint",
                sec_peer_epoch_local: "Local Handshake Epoch",
                sec_peer_epoch_peer: "Peer Handshake Epoch",
                sec_peer_copy: "Copy",
                sec_peer_close: "Close",
                sec_click_details: "Click for full details and to copy fingerprints",
                no_peers_enc: "No peers connected",
                protocol_dist_title: "🥧 Protocol Traffic Distribution",
                public_unencrypted: "Public Mesh (Unencrypted)",
                encrypted_overlay: "Encrypted Overlay (Noise/PSK)",
                disabled: "Disabled",
                online: "ONLINE (2s Auto Refresh)",
                refresh: "🔄 Refresh",
                settings: "⚙️ Settings",
                tap_ipv4: "IPv4 Address",
                tap_ipv4_sub: "Layer-2 Virtual Ethernet",
                tap_ipv6: "IPv6 Address",
                tap_ipv6_sub: "Native Dual-Stack Transmission",
                tx_bytes: "Tx Data (Sent)",
                rx_bytes: "Rx Data (Received)",
                pkts_total: "Packets: ",
                dedup_count: "Deduplicated Packets",
                dedup_sub: "Multi-link Duplicate Filtering",
                topology_mesh: "🕸️ Live Interactive P2P Topology Mesh",
                topo_filter_label: "Filter:",
                topo_filter_all: "All",
                topo_filter_direct: "Direct",
                topo_filter_relayed: "Relayed",
                topo_click_hint: "Click a node to inspect &amp; highlight its path to self",
                topo_clear_sel: "Close",
                ping_tool: "📡 P2P Network Diagnostics (Ping & Traceroute)",
                troubleshoot_title: "🔧 P2P Connectivity Troubleshooter",
                troubleshoot_select_peer: "Select a Peer to Diagnose",
                troubleshoot_manual_input: "Or enter Peer ID manually...",
                troubleshoot_run: "🔍 Run Full Diagnosis",
                troubleshoot_running: "Running diagnosis...",
                troubleshoot_step1: "Local TAP Interface Check",
                troubleshoot_step2: "Peer Discovery & Connection Status",
                troubleshoot_step3: "libp2p Stream Connectivity Probe",
                troubleshoot_step4: "Transport-Level Multiaddr Probe",
                linkcheck_title: "🔗 Multiaddr Link Check",
                linkcheck_desc: "Deep transport probe: multiaddr valid → DNS resolve → TCP/QUIC → libp2p transport → Noise/TLS handshake → Peer ID match → connection.",
                linkcheck_input_ph: "Enter a full P2P multiaddr, e.g. /ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...",
                linkcheck_btn: "🔗 Run Link Check",
                linkcheck_inline: "🔗 Check",
                linkcheck_inline_title: "Run 7-stage link diagnosis on this multiaddr",
                linkcheck_running: "Running link check…",
                linkcheck_no_input: "Please enter a multiaddr to check.",
                linkcheck_overall: "Overall",
                linkcheck_peer: "Target Peer",
                linkcheck_input: "Tested Multiaddr",
                linkcheck_transport: "Transport",
                linkcheck_resolved: "Resolved IPs",
                linkcheck_step1: "Multiaddr Valid",
                linkcheck_step2: "DNS Resolves",
                linkcheck_step3: "TCP / QUIC Established",
                linkcheck_step4: "libp2p Transport",
                linkcheck_step5: "Noise / TLS Handshake",
                linkcheck_step6: "Peer ID Match",
                linkcheck_step7: "libp2p Connection",
                troubleshoot_step5: "Overlay Routing Path Analysis",
                troubleshoot_step6: "ARP/NDP Resolution Check",
                troubleshoot_step7: "ACL & Security Policy Check",
                troubleshoot_pass: "PASS",
                troubleshoot_fail: "FAIL",
                troubleshoot_warn: "WARN",
                troubleshoot_skip: "SKIP",
                troubleshoot_running: "RUNNING",
                troubleshoot_step8: "TAP Device Read/Write Self-Test",
                troubleshoot_step8_running: "Running TAP device read/write self-test…",
                troubleshoot_step8_unavailable: "TAP self-test unavailable on this node.",
                troubleshoot_step8_stale_binary: "The /api/tap/selftest endpoint did not answer with JSON. The running binary is likely outdated — rebuild and restart p2ptap.",
                troubleshoot_step8_write_fail: "TAP write path FAILED.",
                troubleshoot_step8_device: "Device",
                troubleshoot_step8_wintun_noloop: "no loopback — Wintun is an L3 tunnel, expected",
                troubleshoot_step8_loopback_ok: "loopback verified",
                troubleshoot_step8_loopback_fail: "expected TAP loopback, but no frame read back",
                troubleshoot_step8_request_fail: "TAP self-test request failed",
                troubleshoot_step9: "End-to-End TAP Data-Path Forwarding Test",
                troubleshoot_step9_running: "Injecting a TAP frame (ICMP echo request) into the overlay toward the peer's TAP IP…",
                troubleshoot_step9_pass: "TAP frame round-trip OK (ICMP echo request → peer → ICMP echo reply).",
                troubleshoot_step9_sent: "Sent",
                troubleshoot_step9_fail: "TAP forwarding test failed.",
                troubleshoot_step9_fail_detail: "TAP forwarding test failed — the TAP data path is broken even though echo (Step 7) passed.",
                troubleshoot_step9_hint: "Likely a broken overlay unicast/relay path or a peer-side TAP frame handling issue. Check the relay path and peer TAP device.",
                troubleshoot_step9_request_fail: "TAP forwarding test request failed",
                common_ok: "OK",
                common_failed: "FAILED",
                common_idle: "idle",
                common_write: "Write",
                common_read: "Read",
                common_unknown_write_error: "unknown write error",
                common_peer: "Peer",
                common_rtt: "RTT",
                common_unknown: "unknown error",
                troubleshoot_no_peer: "Please select or enter a peer to diagnose",
                troubleshoot_idle: "Select a peer and click 'Run Full Diagnosis' to start troubleshooting connectivity issues.",
                run_ping: "🚀 Run Ping Test",
                run_trace: "🔍 Run P2P Traceroute",
                ping_placeholder: "e.g. 10.0.0.2 or 12D3KooW...",
                active_peers: "⚡ Active P2P Peers",
                routes_table: "🛣️ Smart P2P Overlay Routing Table",
                stat_total_routes: "Total Computed Routes",
                stat_relayed_routes: "Relay Accelerated Paths",
                stat_max_savings: "Max Latency Reduction",
                stat_mesh_health: "Mesh Topology Health",
                arp_table: "📋 Virtual Network ARP / NDP Neighbor Table",
                ip_analytics: "📊 24-Hour Per-IP Traffic Analytics",
                mac_table: "🔀 Virtual Switch MAC Address Table",
                no_routes: "No routing entries computed yet",
                col_dest: "Destination Node",
                col_hops: "Hops",
                col_optimal_path: "Visual Route Path",
                col_total_rtt: "Optimal RTT",
                col_direct_rtt: "Direct RTT",
                col_optimization: "Smart Acceleration",
                col_route_status: "Route Status",
                col_inspector: "Decision Inspector",
                inspect_btn: "🔍 Inspect",
                inspector_title: "🧭 Smart Routing Decision Inspector",
                target_node: "🎯 Target Node",
                eval_table_title: "📊 Dijkstra Routing Engine - Evaluated Candidate Paths",
                col_status: "Status",
                col_candidate_path: "Candidate Path",
                col_rtt_end: "End-to-End RTT",
                col_rationale: "Decision / Rejection Rationale",
                chosen_optimal: "🟢 Chosen Optimal",
                rejected: "❌ Rejected",
                unreachable: "Unreachable",
                direct_optimal_title: "Direct P2P Chosen (Lowest Latency)",
                direct_optimal_desc: "Direct physical latency is faster than any candidate multi-hop relay route",
                relay_chosen_title: "Smart Relay Chosen",
                relay_accel_active: "Relay Acceleration Active",
                relay_accel_desc: "Dijkstra algorithm computed multi-hop path via",
                saved_latency: "saved",
                vs_direct: "compared to direct path",
                nat_fallback_desc: "bypasses Symmetric NAT isolation where direct P2P link is unreachable",
                col_nodename: "Node Name",
                col_role: "Node Role",
                col_osarch: "OS / Arch",
                col_tapip: "PEER IP",
                col_tapmac: "TAP MAC",
                col_tap_ip: "Virtual IP",
                col_nat: "NAT Status",
                col_peerid: "Peer ID",
                col_multiaddr: "Network Multiaddr",
                col_transport: "Transport",
                col_uptime: "Uptime",
                col_rtt: "RTT Latency",
                col_ip: "IP Address",
                col_mac: "MAC Address",
                col_rate: "Live Rate",
                col_ip_attr: "Node / Scope",
                col_target_peer: "Associated Peer ID",
                col_type: "Type",
                col_tx_traffic: "Tx Traffic",
                col_rx_traffic: "Rx Traffic",
                col_total_traffic: "Total Traffic",
                col_pkts: "Packets",
                col_last_active: "Last Active Time",
                ip_scope_local: "Local TAP",
                ip_scope_peer: "Mesh Peer",
                ip_scope_subnet: "LAN Subnet",
                ip_scope_exit: "Exit Gateway",
                ip_scope_special: "L2 Special",
                ip_scope_wan: "WAN Internet",
                btn_disconnecting: "Disconnecting...",
                topo_badge_peer: "Mesh Peer",
                via: "via",
                no_peers: "No active P2P peers connected",
                no_arps: "No entries in ARP table",
                no_ips: "No per-IP traffic recorded yet",
                no_macs: "No entries in MAC table",
                col_mac_origin: "Source",
                mac_origin_self: "Peer Iface",
                mac_origin_lan: "Fwd LAN",
                mac_origin_self_tip: "This peer's own virtual TAP interface MAC (locally administered, starts 02:xx:…). One per healthy peer.",
                mac_origin_lan_tip: "A device on this peer's LAN (bridged / forwarded), NOT the peer itself. Several entries mean the peer is relaying its LAN traffic.",
                mac_lan_warn: "Peer {peer} is forwarding {n} LAN device(s) — normal when the peer bridges / forwards its LAN, not a fault.",
                retrieving_metrics: "Retrieving peer link metrics...",
                modal_title: "⚙️ p2ptap Node Configuration",
                node_name_lbl: "Node Name",
                strategy_lbl: "Transport Strategy",
                psk_lbl: "Pre-Shared Key (PSK)",
                psk_placeholder: "Leave empty for public network, set key for encrypted isolation",
                loglevel_lbl: "Log Level",
                obfs_lbl: "Obfuscation Mode",
                obfs_jitter_lbl: "Jitter Range (±bytes)",
                obfs_jitter_desc: "Random jitter to break fixed-size patterns (0=off)",
                obfs_fixed_size_lbl: "Fixed Packet Size",
                obfs_fixed_size_desc: "Target frame size for fixed/dynamic-max (bytes)",
                obfs_dynamic_lbl: "Dynamic Size Range (bytes)",
                obfs_dynamic_desc: "Min–Max range for variable-size frames",
                obfs_block_size_lbl: "Block Alignment Size",
                obfs_block_size_desc: "Alignment granularity for block mode (bytes)",
                obfs_max_safe_lbl: "Max Safe Frame Size",
                obfs_max_safe_desc: "PMTU safety threshold for obfuscated frames (bytes)",
                obfs_auto_title: "🤖 Auto-Detect Settings",
                obfs_eval_interval_lbl: "Eval Interval",
                obfs_threshold_lbl: "Threshold",
                obfs_allow_switch_lbl: "Allow Automatic Mode Switching",
                obfs_strict_key_lbl: "Strict Key Negotiation (PFS)",
                obfs_strict_key_desc: "Forbid falling back to the long-lived node key. Each peer pair must derive its own cipher from a one-shot ECDH ephemeral key; otherwise that peer stays plaintext. Hardens per-pair key isolation.",
                bootstrap_lbl: "Bootstrap Peers",
                section_identity: "Node Identity",
                section_identity_desc: "Name and encryption settings for this node",
                node_name_desc: "Human-readable identifier for the dashboard",
                psk_desc: "Empty for public network, set key for encrypted isolation",
                section_transport: "Transport & Logging",
                section_transport_desc: "Routing strategy and diagnostic verbosity",
                strategy_desc: "How packets are routed across P2P links",
                loglevel_desc: "Controls verbosity of console output",
                enable_mdns_lbl: "Enable mDNS LAN Discovery",
                enable_mdns_desc: "Auto-discover peers on the same LAN via mDNS (local network only)",
                cfg_disable_relay_lbl: "Disable Circuit Relay (diagnostic)",
                cfg_disable_relay_desc: "Turn OFF libp2p circuit-relay client/service, AutoRelay & DCUtR hole-punching. Requires restart. If a slow peer becomes unreachable with this ON, it was being auto-relayed through a static relay. Does NOT touch p2ptap's own overlay relay.",
                section_obfs: "Traffic Obfuscation",
                section_obfs_desc: "Packet padding to defeat DPI fingerprinting",
                obfs_mode_desc: "Padding strategy for P2P data frames",
                section_bootstrap: "Bootstrap Peers",
                section_bootstrap_desc: "Initial relay nodes for network discovery",
                bootstrap_placeholder: "One multiaddr per line",
                cfg_add_item: "➕ Add",
                cfg_list_empty: "No items yet.",
                drag_handle_tip: "Drag to reorder",
                drag_rule_tip: "Drag to reorder rule",
                move_up_tip: "Move up",
                move_down_tip: "Move down",
                acl_action_accept: "ACCEPT",
                acl_action_drop: "DROP",
                acl_dir_both: "↔ Both",
                acl_dir_in: "↓ Inbound",
                acl_dir_out: "↑ Outbound",
                acl_proto_any: "ANY",
                acl_proto_tcp: "TCP",
                acl_proto_udp: "UDP",
                acl_proto_icmp: "ICMP",
                acl_no_rules_short: "No custom ACL rules defined (click \"+ Add Rule\" to create one)",
                exit_node_title: "🌐 Exit Node Gateway Settings",
                exit_node_desc: "Internet egress routing via this node",
                exit_enable_lbl: "Enable Exit Node Gateway Mode",
                exit_enable_desc: "Route internet traffic through this peer",
                exit_nat_lbl: "Enable SNAT / Masquerade (Source Address Translation)",
                exit_nat_desc: "Source address translation for outbound traffic",
                exit_wan_lbl: "WAN Egress Interface (e.g. eth0 or auto)",
                section_subnet_title: "🌐 Subnet Router & Authorization",
                section_subnet_desc: "Route subnets and authorize which peers may use them",
                adv_subnets_lbl: "Advertised Subnets (CIDR, one per line)",
                accept_subnets_lbl: "Accept Advertised Subnets from Remote Peers",
                allowed_subnet_peers_lbl: "Allowed Subnet Peer IDs (* for trust all, one per line)",
                section_acl_title: "🛡️ ZeroTier-Style P2P Mesh ACL Rules Editor",
                section_acl_desc: "Per-peer traffic filtering rules",
                add_rule_btn: "➕ Add Rule",
                enable_acl_lbl: "Enable ACL Firewall Engine",
                acl_default_action_lbl: "Default Policy for Unmatched Traffic",
                acl_flow_title: "Sequential Rules Flow:",
                acl_flow_hint_permit: "Permit-exception list — these rules ALLOW matching traffic despite the default-DROP policy.",
                acl_flow_hint_block: "Block-exception list — these rules DENY matching traffic despite the default-ACCEPT policy.",
                exit_node_badge: "🌐 Exit Node",
                set_as_exit_btn: "🚀 Set as Gateway",
                clear_exit_node_btn: "🛑 Disconnect Exit",
                active_exit_badge: "⚡ Active Gateway",
                exit_connected: "🚀 Exit gateway connected to ",
                exit_disconnected: "🛑 Exit gateway disconnected",
                peer_traffic_title: "Peer Live Broadcasted Rate & Traffic",
                topo_reset_layout: "📌 Reset Layout",
                topo_reset_zoom: "🔍 Reset View",
                bandwidth_chart_title: "📈 Live Bandwidth Waveform (Tx / Rx)",
                packet_rate_title: "📊 Packet Rate Distribution (Tx / Rx)",
                mesh_matrix_title: "🕸️ Mesh Quality & Latency Matrix",
                matrix_src: "Source Node",
                matrix_dst: "Destination Node",
                matrix_rtt: "RTT Latency",
                matrix_hops: "Hops",
                matrix_type: "Link Type",
                no_matrix: "No peer routes in matrix",
                subnet_routes_title: "🌐 Subnet Routes",
                no_subnets: "No advertised subnets active",
                dup_ip_conflicts_title: "⚠️ Duplicate IP / Subnet Conflicts",
                no_dup_ip_conflicts: "No duplicate IP or subnet conflicts detected",
                dup_winner: "Winner",
                peer_meta_title: "📡 Peer Metadata & Peek-Map Discovery Monitor",
                col_subnets: "Advertised Subnets",
                col_exit_egress: "Exit Node Egress",
                col_sync_channel: "Discovery Channel",
                col_last_sync: "Last Heard",
                no_peer_metas: "No peer metadata received via peek-map / P2P",
                exit_client_card_title: "🚀 Exit Node Gateway Control",
                exit_client_status_active: "⚡ Routing all internet traffic via Exit Node",
                exit_client_status_inactive: "No Exit Gateway active (using local default gateway)",
                exit_client_no_peers: "No online peers currently offering Exit Node egress",
                btn_connect_exit: "🚀 Connect Exit Gateway",
                exit_picker_hint: "Select a peer above to route traffic through",
                btn_disconnect_exit: "⏹️ Disconnect Exit",
                btn_enable_subnet: "▶️ Enable",
                btn_disable_subnet: "🛑 Disable",
                badge_subnet_disabled: "⏸️ Disabled",
                badge_subnet_pending: "⛔ Pending Authorization",
                subnet_no_toggle: "Not routable",
                toast_subnet_enabled: "▶️ Subnet route {cidr} enabled in real-time",
                toast_subnet_disabled: "⏸️ Subnet route {cidr} disabled in real-time",
                acl_status_title: "🛡️ Firewall",
                acl_open_desc: "Mesh Firewall is Open (All P2P Traffic Allowed)",
                acl_badge_open: "Open Mesh",
                acl_badge_active: "● Active",
                acl_open_hint: "Enable ACL in Settings → ACL Editor to enforce rules.",
                acl_label_rules: "Rules",
                acl_label_default: "Default",
                acl_label_accepted: "Accepted",
                acl_label_dropped: "Dropped",
                acl_label_uptime: "Uptime",
                acl_label_top_rules: "Top matched rules",
                acl_label_recent_drops: "Recent drops",
                acl_label_default_action: "default",
                acl_label_hits: "hits",
                acl_label_more: "more",
                acl_default_accept: "ACCEPT (allow)",
                acl_default_drop: "DROP (deny)",
                strategy_redundant: "Dual-Send Redundant",
                strategy_fallback: "Failover Fallback",
                log_level_debug: "Verbose Debug",
                log_level_info: "Standard Info",
                log_level_warn: "Warnings Only",
                log_level_error: "Errors Only",
                obfs_fixed: "Fixed Size Padding",
                obfs_block: "Block Multiple",
                obfs_random: "Random Length",
                obfs_dynamic: "Variable Range",
                obfs_auto: "Auto-Detect & Switch",
                acl_editor_title: "🛡️ ACL Rule Editor",
                acl_no_rules: "No custom ACL rules yet — add one or pick a template.",
                acl_test_title: "🧪 ACL Rule Tester",
                acl_test_peer: "Source Peer ID",
                acl_test_dir: "Direction",
                acl_test_proto: "Protocol",
                acl_test_dstip: "Destination IP",
                acl_test_dstport: "Destination Port",
                acl_test_allow: "ALLOWED",
                acl_test_deny: "DENIED",
                acl_test_matched: "Matched rule",
                acl_test_default: "No rule matched — applied default policy",
                acl_template_lbl: "Insert Template…",
                acl_comment_placeholder: "Comment / Description",
                close_btn: "Close",
                cancel_btn: "Cancel",
                save_btn: "Save & Apply",
                save_success: "Configuration saved successfully!",
                cfg_needs_restart: "⚠️ Disable-relay changed — restart p2ptap to apply.",
                save_failed: "Failed to save configuration: ",
                req_error: "Save request error: ",
                unnamed_node: "Unnamed Node",
                via_exit_node: "🚀 via Exit Node",
                via_exit_node_hint: "Traffic routed out through the selected Exit Node gateway",
                public_direct: "Direct (Public)",
                relayed_conn: "Relayed",
                relay_only: "Relay-Only",
                not_configured: "Not Configured",
                disc_addrs: "Discovered Addr Pathways",
                view_addr: "View Multiaddr",
                active_pathway: "Current Active Connected Pathway",
                active_pathway_unknown: "No live connection",
                best_reachable_pathway: "Best reachable candidate (from last multiaddr probe)",
                probe_unverified: "unverified",
                logs_cleared: "Logs cleared.",
                copied_toast: "📋 Config JSON copied to clipboard!",
                log_count: "{n} Logs",
                log_listening: "Listening for live log events...",
                multiaddr_placeholder: "/ip4/1.2.3.4/udp/4001/quic-v1/p2p/12D3KooW...",
                exit_wan_placeholder: "auto (auto-detect physical egress interface)",
                exit_status_title: "Live Status",
                exit_status_inactive: "No Exit Node tunnel active",
                exit_status_role_client: "Client",
                exit_status_role_server: "Server (offering egress)",
                exit_status_role_both: "Client + Server",
                exit_status_routing_via: "Routing traffic through",
                exit_status_offering: "Offering egress to the mesh",
                exit_status_peer: "Peer",
                exit_status_tap_ip: "TAP IP",
                exit_status_tap_ipv6: "TAP IPv6",
                subnets_placeholder: "e.g. 192.168.1.0/24",
                allowed_peers_placeholder: "e.g. * or 12D3KooW...",
                delete_rule: "🗑️ Delete",
                acl_peer_placeholder: "Peer ID or *",
                acl_cidr_placeholder: "Target CIDR or *",
                acl_port_placeholder: "Port / Range",
                echo_test: "🧪 Echo Test",
                echo_test_hint: "💡 Click any 🧪 Echo Test button to benchmark latency over a specific Multiaddr pathway.",
                test_all: "🧪 Test All",
                speedtest_btn: "⚡ SpeedTest",
                test_echo: "⚡ Test Echo",
                probing_text: "⏳ Probing...",
                probe_result: "🧪 {reachable}/{total} addresses reachable",
                probe_error: "🧪 Probe error",
                probing_echo: "🚀 Probing Echo stream via {addr}...",
                probing_pathways_title: "🧪 Probing Multiaddr Pathways...",
                probing_pathways_desc: "Testing stream reachability, RTT, and transport types...",
            },
            "zh-CN": {
                default_node_name: "P2P TAP 虚拟专网节点",
                login_title: "🔐 P2P TAP 仪表盘登录",
                login_subtitle: "此仪表盘受保护，请输入访问令牌以继续。",
                login_token_label: "访问令牌",
                login_token_placeholder: "粘贴启动日志或配置 (webui.auth_token) 中的令牌",
                login_btn: "登录",
                login_error: "令牌无效或请求失败，请重试。",
                login_hint: "令牌会保存在本地浏览器中，并作为 Bearer 请求头发送。",
                topology_title: "🗺️ 拓扑星图",
                topology_sub: "(拖拽节点调整位置 | 滚轮缩放画布 | 双击节点发起 Ping 测速)",
                reset_view: "🎯 重置视角",
                topo_standalone: "🌐 独立 Overlay 节点 (等待 P2P 对端加入中...)",
                topo_self_node: "本机节点",
                protocol_inspector_title: "📊 实时以太网协议与数据包分析器",
                protocol_inspector_desc: "(二/三/四层数据包抓包分析与 PPS 速率统计)",
                proto_channels_title: "📡 协议通道与流状态监测",
                th_stream_proto: "协议 / 通道标识",
                th_stream_peer: "对端节点",
                th_stream_direction: "流方向",
                th_stream_transport: "传输层与 Multiaddr 链路",
                th_stream_status: "状态",
                search_streams_ph: "搜索流、协议、对端节点…",
                no_matching_streams: "未找到活跃协议流",
                no_channels: "未找到活跃协议通道",
                lbl_active_streams: "条活跃流",
                lbl_streams: "条流",
                dir_out: "出站 ↑",
                dir_in: "入站 ↓",
                stream_active: "活跃中",
                channel_status_active: "活跃",
                channel_status_running: "运行中",
                channel_status_idle: "空闲",
                channel_status_standby: "待命",
                channel_status_ready: "就绪",
                channel_status_open: "开放模式",
                category_sync: "同步",
                category_routing: "路由",
                category_pubsub: "发布订阅",
                category_data: "数据传输",
                category_security: "安全隔离",
                category_transport: "传输层",
                category_diagnostics: "诊断",
                category_discovery: "发现",
                channel_seqsync_name: "序号同步 (SeqSync)",
                channel_seqsync_desc: "窗口去重与重放防护",
                channel_lsa_name: "LSA 链路状态路由",
                channel_lsa_desc: "Dijkstra 最短路径选路",
                channel_peekmap_name: "Peek-Map 全网拓扑广播",
                channel_peekmap_desc: "引导拓扑发现与同步",
                channel_data_name: "虚拟 TAP 数据通路",
                channel_data_proto: "二层以太网数据链路",
                channel_auth_name: "PSK Mesh 身份认证",
                channel_auth_desc: "PSK Mesh 网络安全隔离",
                channel_dcutr_name: "DCUtR 自动打洞与中继",
                channel_dcutr_desc: "NAT 直连打洞自动升级",
                cipher_lbl: "加密算法",

                lbl_arp_broadcast: "ARP 广播以太帧",
                lbl_broadcast_pkts: "广播包",
                lbl_multicast_pkts: "组播包",
                lbl_gateway_pkts: "网关包 (Exit Node)",
                desc_broadcast: "二层广播 (含 ARP)",
                desc_multicast: "二层组播 (含 mDNS)",
                desc_gateway: "经 Exit Node 隧道转发",
                lbl_seq_sync: "Seq 同步与去重",
                desc_seq_sync: "已同步节点数 · 重放/窗口丢弃",
                lbl_icmp_ping: "ICMP (Ping) 报文",
                lbl_udp_packets: "UDP 传输数据包",
                lbl_tcp_packets: "TCP 流数据包",
                desc_arp: "二层 MAC 地址解析",
                desc_icmp: "网络链路探测与保活",
                desc_udp: "数据报无连接传输",
                desc_tcp: "可靠字节流传输",
                // ── Topology tooltip labels (node hover) ──
                topo_tt_local_host: "本机",
                topo_tt_ipv4: "虚拟 IPv4:",
                topo_tt_ipv6: "虚拟 IPv6:",
                topo_tt_peer_id: "Peer ID:",
                topo_tt_route: "路由:",
                topo_tt_direct_link: "直连 P2P 链路",
                topo_tt_circuit_relay: "电路中继 v2",
                topo_tt_optimal_route: "最优路由:",
                topo_tt_route_gain: "路由收益:",
                topo_tt_transit_relay: "中继转发",
                topo_tt_seq: "序列号 (Tx/Rx):",
                topo_tt_dedup_window: "去重窗口:",
                topo_tt_dup_drops: "重复丢弃数:",
                topo_tt_link_integrity: "链路完整性:",
                topo_tt_blackhole: "Rx 黑洞 (去重偏移)",
                topo_tt_healthy: "健康",
                topo_tt_os_arch: "系统 / 架构:",
                topo_tt_tap_ip: "PEER IP:",
                topo_tt_transport: "传输层:",
                topo_tt_rtt: "RTT 延迟:",
                topo_tt_live_rate: "实时速率:",
                topo_tt_uptime: "运行时间:",
                topo_legend_direct_fast: "● 直连 (<30ms)",
                topo_legend_direct_slow: "● 直连 (30-100ms)",
                topo_legend_relay: "● 电路中继 (>100ms)",
                topo_legend_flow: "💧 流量密度 = 实际 TX/RX 速率（空闲链路无流量）",
                topo_badge_transit: "🌉 中转交换机",
                topo_badge_exit_server: "🚪 出口服务端",
                topo_via: "经",
                topo_link_idle: "空闲",
                topo_summary_nodes: "节点",
                topo_summary_direct: "直连",
                topo_summary_relayed: "经中继",
                topo_summary_relays: "中转节点",
                topo_summary_thru: "网格吞吐",
                topo_summary_gw: "网关包",
                topo_summary_boots: "引导节点",
                topo_summary_static: "静态节点",
                topo_summary_clusters: "集群",
                topo_filter_remote: "跨集群",
                topo_legend_boot: "● 引导节点 (紫色)",
                topo_legend_overlay: "◆ 覆盖中继 (长虚线)",
                topo_badge_boot: "引导",
                topo_badge_static: "静态",
                topo_tt_role_boot: "引导节点",
                topo_tt_role_static: "静态节点",
                topo_tt_cluster: "集群:",
                topo_tt_boot_hops: "引导跳数:",
                topo_tt_transport_path: "传输路径:",
                topo_tt_relay_hop: "中继跳:",
                topo_tt_enc: "加密:",
                topo_tt_conn: "连接状态:",
                topo_tt_jitter: "抖动:",
                topo_tt_loss: "丢包率:",
                topo_tt_version: "版本:",
                topo_tt_since: "已连接:",
                topo_tt_geo: "位置:",
                topo_tt_total: "累计 (发/收):",
                topo_tt_route_via: "路径:",
                modal_add_static_title: "➕ 添加永久 Static 静态节点",
                modal_add_static_desc: "输入包含目标 /p2p/<PEER_ID> 的完整 Multiaddr。该地址将赋予 PermanentAddrTTL 永久保存在 Peerstore 并自动重连。",
                lbl_multiaddr_str: "Multiaddr 节点地址字符串",
                btn_cancel: "取消",
                btn_test_save_peer: "➕ 探活并保存永久静态节点",
                modal_diag_title: "⚡ Peer 物理链路诊断与基准测试",
                btn_close: "关闭",
                btn_add_static_peer: "➕ 添加 Static 节点",
                pcap_title: "🔬 抓包 (Packet Capture)",
                pcap_stopped: "已停止",
                pcap_running: "● 捕获中",
                pcap_start: "▶️ 开始",
                pcap_pause: "⏸️ 暂停",
                pcap_clear: "🗑️ 清除",
                pcap_autoscroll: "自动滚动",
                pcap_stream_live: "实时推送 (WebSocket)",
                pcap_stream_connecting: "正在连接…",
                pcap_stream_polling: "轮询回退（实时推送不可用）",
                pcap_stream_off: "推送已断开",
                pcap_stream_dropped: "客户端处理慢，已丢帧",
                log_stream_live: "实时推送 (WebSocket)",
                log_stream_connecting: "正在连接…",
                log_stream_polling: "轮询回退（实时推送不可用）",
                log_stream_off: "推送已断开",
                log_stream_dropped: "客户端处理慢，已丢日志",
                pcap_desc: "抓取本机 TAP 虚拟网卡收发的原始以太网帧（含源/目的 MAC、协议、IP、十六进制）。<span class=\"tx-tag\">tx</span> = 本机发出，<span class=\"rx-tag\">rx</span> = 本机收到。<span class=\"tx-tag\">点击任意一行</span>可查看完整详情与原始帧十六进制。",
                pcap_empty: "暂无数据。点击「开始」捕获本机 TAP 流量。",
                pcap_click_hint: "点击查看完整详情",
                pcap_dup_repeat: "重复帧 — 与上一行完全一致 (mDNS / 多播重传)",
                pcap_dup_repeat_row: "重复帧 — 与上一行 payload 完全相同。这是 mDNS / 多播重传的正常现象，不是渲染重复。",
                pcap_modal_title: "🔬 数据包详情",
                pcap_modal_raw: "完整十六进制 (raw frame)",
                pcap_copy_hex: "📋 复制 Hex",
                pcap_dir_tx: "本机发出 (tx)",
                pcap_dir_rx: "本机收到 (rx)",
                pcap_f_seq: "序号",
                pcap_f_time: "时间",
                pcap_f_dir: "方向",
                pcap_f_srcmac: "源 MAC",
                pcap_f_dstmac: "目的 MAC",
                pcap_f_etype: "EtherType",
                pcap_f_proto: "协议",
                pcap_f_vlan: "VLAN ID",
                pcap_f_l4proto: "L4 协议",
                pcap_f_srcip: "源 IP",
                pcap_f_dstip: "目的 IP",
                pcap_f_srcport: "源端口",
                pcap_f_dstport: "目的端口",
                pcap_f_tcpflags: "TCP 标志位",
                pcap_f_tcpseq: "TCP 序号",
                pcap_f_tcpwin: "TCP 窗口",
                pcap_f_dns: "DNS 查询",
                pcap_f_sni: "TLS SNI",
                pcap_f_ttl: "TTL",
                pcap_f_arpop: "ARP 操作",
                pcap_f_arpsmac: "ARP 发送方 MAC",
                pcap_f_arpdmac: "ARP 目标 MAC",
                pcap_f_frompeer: "发出 Peer",
                pcap_f_topeer: "送达 Peer",
                pcap_f_len: "帧长度",
                pcap_f_info: "协议摘要",
                pcap_layer_frame: "帧",
                pcap_layer_tree: "协议分层解析",
                pcap_col_seq: "#",
                pcap_col_time: "时间",
                pcap_col_dir: "方向",
                pcap_col_srcmac: "源 MAC",
                pcap_col_dstmac: "目的 MAC",
                pcap_col_etype: "类型",
                pcap_col_proto: "协议",
                pcap_col_srcip: "源 IP",
                pcap_col_dstip: "目的 IP",
                pcap_col_ports: "端口",
                pcap_col_flags: "标志",
                pcap_col_dns: "DNS",
                pcap_col_sni: "SNI",
                pcap_col_frompeer: "发出 Peer",
                pcap_col_topeer: "送达 Peer",
                pcap_col_len: "长度",
                pcap_col_info: "摘要",
                pcap_col_hex: "Hex(前64B)",
                err_enter_multiaddr: "请输入有效的 Multiaddr 节点地址",
                toast_testing_adding: "正在测试并添加静态节点",
                toast_static_added: "静态节点已成功添加并赋予永久存续 (PermanentAddrTTL)！",
                toast_add_failed: "添加静态节点失败",
                toast_req_err: "请求异常",
                speed_test: "⚡ P2P 测速",
                share_config: "📲 分享与导出",
                terminal_title: "📟 实时日志",
                auto_scroll: "📜 自动滚动: 开启",
                auto_scroll_off: "📜 自动滚动: 关闭",
                clear_logs: "清空",
                pause_logs: "⏸️ 暂停",
                resume_logs: "▶️ 继续",
                log_paused_badge: "⏸ 已暂停",
                copy_logs: "📋 复制",
                logs_copied: "📋 日志已复制到剪贴板！",
                logs_empty_copy: "暂无日志可复制。",
                copy_failed: "复制失败。",
                speedtest_title: "⚡ P2P 链路带宽与延迟性能测速",
                select_target_peer: "选择目标测速节点",
                mbps_label: "Mbps (P2P 传输吞吐速率)",
                rtt_avg: "平均延迟 RTT",
                jitter_lbl: "网络抖动 Jitter",
                quality_lbl: "链路质量",
                start_test_btn: "🚀 开始性能测速",
                share_title: "📲 配置导出与二维码分享",
                share_desc: "扫描二维码或复制 JSON 配置文件以进行节点部署。",
                copy_json: "📋 复制 JSON",
                download_json: "💾 下载配置文件",
                col_geo: "地理位置归属",
                col_conn_time: "已连接时长",
                col_last_active: "上次通信时间",
                col_jitter_loss: "抖动 / 丢包率",
                col_status: "连接状态",
                col_return_path: "回程状态",
                conn_ok: "已连接",
                conn_relay_ok: "中继正常",
                conn_connecting: "连接中",
                conn_proto_mismatch: "协议不匹配",
                conn_obf_failed: "解密失败",
                conn_unreachable: "不可达",
                return_ok: "回程正常",
                return_dead: "回程断",
                return_idle: "回程未知",
                col_actions: "操作",
                topo_tx: "去程链路 (Tx ➔)",
                topo_rx: "回程链路 (Rx ⬅️)",
                topo_relay: "多跳中转链路",
                peer_id_lbl: "节点ID",
                strategy_best_path: "最佳路径",
                strategy_low_latency: "最低延迟",
                strategy_high_bandwidth: "高带宽",
                search_placeholder: "搜索…",
                prev_page: "‹ 上一页",
                next_page: "下一页 ›",
                per_page: "每页",
                no_match: "无匹配",
                sys_health_title: "💻 系统与运行时健康状态",
                badge_active: "运行中",
                lbl_heap: "堆内存已用 / 总分配:",
                lbl_goroutines: "Goroutine 协程数:",
                lbl_gc_runs: "垃圾回收 (GC) 次数:",
                lbl_process_uptime: "进程在线时长:",
                lbl_heap_inuse: "堆内存实际占用:",
                lbl_heap_objects: "堆上活对象数:",
                lbl_stack_inuse: "协程栈总用量:",
                lbl_next_gc: "下次 GC 触发:",
                lbl_last_gc_pause: "上次 GC 暂停:",
                lbl_gc_cpu: "GC 占 CPU 比例:",
                lbl_gomaxprocs: "调度并行度:",
                lbl_cpu_cores: "CPU 核数:",
                security_title: "🛡️ 安全与加密防护状态",
                badge_protected: "受防护",
                lbl_psk_status: "PSK 预共享密钥隔离:",
                lbl_traffic_obfs: "数据包流量混淆:",
                lbl_id_fingerprint: "节点身份密钥指纹:",
                lbl_autonat_reach: "AutoNAT 网络可达性:",
                lbl_per_peer_enc: "逐节点加密状态:",
                sec_copy: "复制",
                sec_copied: "已复制",
                sec_peer_title: "节点加密详情",
                sec_peer_id: "节点 ID",
                sec_peer_algo: "加密算法",
                sec_peer_pfs: "前向保密 (PFS)",
                sec_yes: "是",
                sec_no: "否",
                sec_peer_tx_fp: "TX 密钥指纹 (SHA-256 前 8 位)",
                sec_peer_rx_fp: "RX 密钥指纹 (SHA-256 前 8 位)",
                sec_peer_pfs_eph: "临时 ECDH 公钥指纹",
                sec_peer_epoch_local: "本端握手 epoch",
                sec_peer_epoch_peer: "对端握手 epoch",
                sec_peer_copy: "复制",
                sec_peer_close: "关闭",
                sec_click_details: "点击查看完整信息并复制指纹",
                no_peers_enc: "暂无已连接节点",
                protocol_dist_title: "🥧 虚拟网卡以太帧协议分布",
                public_unencrypted: "公共 Overlay (未加密)",
                encrypted_overlay: "加密 Overlay (Noise/PSK)",
                disabled: "未启用",
                online: "在线 (2秒自动刷新)",
                refresh: "🔄 手动刷新",
                settings: "⚙️ 参数设置",
                tap_ipv4: "IPv4 地址",
                tap_ipv4_sub: "二层虚拟以太网",
                tap_ipv6: "IPv6 地址",
                tap_ipv6_sub: "原生 IPv6 双栈传输支持",
                tx_bytes: "发送数据 (TX)",
                rx_bytes: "接收数据 (RX)",
                pkts_total: "包总计: ",
                dedup_count: "冗余过滤包 (Dedup)",
                dedup_sub: "多链路重复包去重过滤",
                topology_mesh: "🕸️ 在线 P2P 拓扑星状图",
                topo_filter_label: "筛选：",
                topo_filter_all: "全部",
                topo_filter_direct: "直连",
                topo_filter_relayed: "经中继",
                topo_click_hint: "单击节点可查看详情并高亮其到本机的路径",
                topo_clear_sel: "关闭",
                ping_tool: "📡 P2P 链路网络诊断 (Ping & Traceroute)",
                troubleshoot_title: "🔧 P2P 通联排查工具",
                troubleshoot_select_peer: "选择要诊断的节点",
                troubleshoot_manual_input: "或手动输入 Peer ID...",
                troubleshoot_run: "🔍 运行全面诊断",
                troubleshoot_running: "正在运行诊断...",
                troubleshoot_step1: "本地 TAP 接口检查",
                troubleshoot_step2: "节点发现与连接状态",
                troubleshoot_step3: "libp2p 流连通性探测",
                troubleshoot_step4: "传输层 Multiaddr 探测",
                linkcheck_title: "🔗 Multiaddr 链路检测",
                linkcheck_desc: "传输层深度探测：multiaddr 合法 → DNS 解析 → TCP/QUIC → libp2p 传输 → Noise/TLS 握手 → Peer ID 匹配 → 连接成功。",
                linkcheck_input_ph: "输入完整 P2P multiaddr，如 /ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...",
                linkcheck_btn: "🔗 运行链路检测",
                linkcheck_inline: "🔗 检测",
                linkcheck_inline_title: "对此 multiaddr 运行 7 段链路诊断",
                linkcheck_running: "正在运行链路检测…",
                linkcheck_no_input: "请输入要检测的 multiaddr。",
                linkcheck_overall: "总体结论",
                linkcheck_peer: "目标 Peer",
                linkcheck_input: "测过那个地址",
                linkcheck_transport: "传输层",
                linkcheck_resolved: "解析出的 IP",
                linkcheck_step1: "Multiaddr 合法",
                linkcheck_step2: "DNS 解析",
                linkcheck_step3: "TCP / QUIC 建立",
                linkcheck_step4: "libp2p 传输层",
                linkcheck_step5: "Noise / TLS 握手",
                linkcheck_step6: "Peer ID 匹配",
                linkcheck_step7: "libp2p 连接成功",
                troubleshoot_step5: "Overlay 路由路径分析",
                troubleshoot_step6: "ARP/NDP 解析检查",
                troubleshoot_step7: "ACL 防火墙与安全策略检查",
                troubleshoot_pass: "通过",
                troubleshoot_fail: "失败",
                troubleshoot_warn: "警告",
                troubleshoot_skip: "跳过",
                troubleshoot_running: "运行中",
                troubleshoot_step8: "TAP 设备读写自检",
                troubleshoot_step8_running: "正在运行 TAP 设备读写自检…",
                troubleshoot_step8_unavailable: "本节点不支持 TAP 自检。",
                troubleshoot_step8_stale_binary: "/api/tap/selftest 接口未返回 JSON，当前运行的二进制很可能是旧版本，请重新编译并重启 p2ptap。",
                troubleshoot_step8_write_fail: "TAP 写入路径失败。",
                troubleshoot_step8_device: "设备",
                troubleshoot_step8_wintun_noloop: "无回环 —— Wintun 为 L3 隧道，属正常现象",
                troubleshoot_step8_loopback_ok: "回环验证通过",
                troubleshoot_step8_loopback_fail: "期望 TAP 回环，但未读回任何帧",
                troubleshoot_step8_request_fail: "TAP 自检请求失败",
                troubleshoot_step9: "端到端 TAP 数据路径转发测试",
                troubleshoot_step9_running: "正在向对端 TAP IP 注入 TAP 帧（ICMP echo request）…",
                troubleshoot_step9_pass: "TAP 帧往返正常（ICMP echo request → 对端 → ICMP echo reply）。",
                troubleshoot_step9_sent: "已发送",
                troubleshoot_step9_fail: "TAP 转发测试失败。",
                troubleshoot_step9_fail_detail: "TAP 转发测试失败 —— 即使 echo（第 7 步）通过，TAP 数据路径仍然不通。",
                troubleshoot_step9_hint: "很可能是 overlay 单播/中继路径断开，或对端 TAP 帧处理异常。请检查中继路径与对端 TAP 设备。",
                troubleshoot_step9_request_fail: "TAP 转发测试请求失败",
                common_ok: "正常",
                common_failed: "失败",
                common_idle: "空闲",
                common_write: "写入",
                common_read: "读取",
                common_unknown_write_error: "未知写入错误",
                common_peer: "节点",
                common_rtt: "往返时延",
                common_unknown: "未知错误",
                troubleshoot_no_peer: "请选择或输入要诊断的节点",
                troubleshoot_idle: "选择一个节点并点击“运行全面诊断”开始排查通联问题。",
                run_ping: "🚀 运行 Ping 测试",
                run_trace: "🔍 运行 P2P 路径追踪",
                ping_placeholder: "例如 10.0.0.2 或 12D3KooW...",
                active_peers: "⚡ 在线 P2P 节点",
                routes_table: "🛣️ 智能 P2P Overlay 路由表",
                stat_total_routes: "已计算的路由总数",
                stat_relayed_routes: "智能中转加速路径",
                stat_max_savings: "最大延迟优化节省",
                stat_mesh_health: "Overlay 网状拓扑状态",
                arp_table: "📋 虚拟网络 ARP / NDP 邻居表",
                ip_analytics: "📊 24小时 IP 流量统计",
                mac_table: "🔀 虚拟交换机 MAC 地址表",
                no_routes: "路由表中暂无计算出的路径",
                col_dest: "目标节点",
                col_hops: "跳数",
                col_optimal_path: "可视化路由图谱",
                col_total_rtt: "最优 RTT",
                col_direct_rtt: "直连 RTT",
                col_optimization: "智能加速效果",
                col_route_status: "路由状态",
                col_inspector: "选路决策分析",
                inspect_btn: "🔍 评估决策",
                inspector_title: "🧭 智能选路决策分析仪",
                target_node: "🎯 目标节点",
                eval_table_title: "📊 Dijkstra 选路引擎 - 全路径候选评估比对",
                col_status: "评估状态",
                col_candidate_path: "候选路径走向",
                col_rtt_end: "端到端 RTT",
                col_rationale: "选路 / 弃用决策原因",
                chosen_optimal: "🟢 最优已选定",
                rejected: "❌ 未采用",
                unreachable: "不可达",
                direct_optimal_title: "选中物理直连 (最低延迟)",
                direct_optimal_desc: "物理直连延迟优于网络中所有可能的中转路由组合",
                relay_chosen_title: "选中中转加速",
                relay_accel_active: "智能中转加速已生效",
                relay_accel_desc: "Dijkstra 算法算得经由",
                saved_latency: "相较于直连线路节省了",
                vs_direct: "直连线路为",
                nat_fallback_desc: "成功绕过 Symmetric NAT 隔离，在直连不可达时维持连通性",
                col_nodename: "节点名称",
                col_role: "节点角色",
                col_osarch: "OS / 架构",
                col_tapip: "PEER IP",
                col_tapmac: "TAP MAC",
                col_tap_ip: "虚拟 IP",
                col_nat: "NAT 状态",
                col_peerid: "Peer ID",
                col_multiaddr: "网络 Multiaddr 地址",
                col_transport: "传输协议",
                col_uptime: "在线时长",
                col_rtt: "RTT 延迟",
                col_ip: "IP 地址",
                col_mac: "MAC 地址",
                col_rate: "实时速率",
                col_ip_attr: "所属节点 / 归属",
                col_target_peer: "关联目标 PeerID",
                col_type: "条目类型",
                col_tx_traffic: "发送流量",
                col_rx_traffic: "接收流量",
                col_total_traffic: "总计流量",
                col_pkts: "数据包计数",
                col_last_active: "最后活跃时间",
                ip_scope_local: "本机 TAP",
                ip_scope_peer: "组网节点",
                ip_scope_subnet: "路由子网",
                ip_scope_exit: "出口网关",
                ip_scope_special: "二层广播/组播",
                ip_scope_wan: "公网 WAN",
                btn_disconnecting: "正在断开...",
                topo_badge_peer: "组网节点",
                via: "经由",
                no_peers: "暂无在线连接的 Peer 节点",
                no_arps: "ARP 列表中暂无数据",
                no_ips: "暂无 IP 流量统计数据",
                no_macs: "MAC 地址表中暂无数据",
                col_mac_origin: "来源",
                mac_origin_self: "节点接口",
                mac_origin_lan: "LAN 转发",
                mac_origin_self_tip: "该 Peer 自身虚拟 TAP 接口 MAC（本地管理地址，以 02:xx:… 开头）。每个健康节点唯一一个。",
                mac_origin_lan_tip: "该 Peer 身后局域网内的设备（经桥接/转发），并非 Peer 自身。出现多个说明此节点在转发其 LAN 流量。",
                mac_lan_warn: "Peer {peer} 正在转发 {n} 个 LAN 设备流量——当该节点桥接/转发其局域网时属正常现象，并非异常。",
                retrieving_metrics: "正在检索节点链路数据...",
                modal_title: "⚙️ p2ptap 节点参数设置",
                node_name_lbl: "节点标识名称",
                strategy_lbl: "传输策略",
                psk_lbl: "预共享密钥 (PSK)",
                psk_placeholder: "留空为公开网络，设置密钥后加密隔离",
                loglevel_lbl: "日志级别",
                obfs_lbl: "混淆模式",
                obfs_jitter_lbl: "抖动范围 (±字节)",
                obfs_jitter_desc: "在固定包长上增加随机抖动打破指纹 (0=关闭)",
                obfs_fixed_size_lbl: "混淆固定包长",
                obfs_fixed_size_desc: "固定填充模式的目标 MTU（字节）",
                obfs_dynamic_lbl: "动态包长范围 (字节)",
                obfs_dynamic_desc: "变量帧填充的最小-最大范围",
                obfs_block_size_lbl: "块对齐粒度",
                obfs_block_size_desc: "块模式填充的步进对齐粒度 (字节)",
                obfs_max_safe_lbl: "最大安全包长 (PMTU 阈值)",
                obfs_max_safe_desc: "混淆分片的物理防分片丢包 PMTU 阈值 (字节)",
                obfs_auto_title: "🤖 动态自适应评估设置",
                obfs_eval_interval_lbl: "评估时间间隔",
                obfs_threshold_lbl: "触发评估流量阈值",
                obfs_allow_switch_lbl: "允许根据流量指纹自动切换模式",
                obfs_strict_key_lbl: "严格密钥协商 (PFS)",
                obfs_strict_key_desc: "禁止回退到长期节点密钥。每对 peer 必须用一次性 ECDH 临时密钥各自派生独立的加密套件，否则该 peer 保持明文。强化每对密钥隔离。",
                bootstrap_lbl: "Bootstrap 中继节点",
                section_identity: "节点身份",
                section_identity_desc: "此节点的名称与加密设置",
                node_name_desc: "在仪表盘中可读的节点标识",
                psk_desc: "留空为公开网络，设置密钥后加密隔离",
                section_transport: "传输与日志",
                section_transport_desc: "路由策略与诊断日志详细程度",
                strategy_desc: "报文在 P2P 链路上的路由方式",
                loglevel_desc: "控制控制台日志输出的详细程度",
                enable_mdns_lbl: "启用 mDNS 局域网节点发现",
                enable_mdns_desc: "通过 mDNS 自动发现同一局域网内的节点（仅限本地网络）",
                cfg_disable_relay_lbl: "禁用标准中继 (排障诊断)",
                cfg_disable_relay_desc: "关闭 libp2p 标准 circuit-relay 客户端/服务端、AutoRelay 和 DCUtR 打洞。需重启生效。若开启后某些慢节点无法访问，说明原先通过静态中继转发。不影响 p2ptap 自有骨干中继。",
                section_obfs: "流量混淆",
                section_obfs_desc: "通过报文填充对抗 DPI 指纹识别",
                obfs_mode_desc: "P2P 数据帧的填充策略",
                section_bootstrap: "Bootstrap 节点",
                section_bootstrap_desc: "用于网络发现的初始中继节点",
                bootstrap_placeholder: "每行输入一个 multiaddr 地址",
                cfg_add_item: "➕ 添加",
                cfg_list_empty: "暂无条目。",
                drag_handle_tip: "拖动以调整顺序",
                drag_rule_tip: "拖动以调整规则顺序",
                move_up_tip: "上移",
                move_down_tip: "下移",
                acl_action_accept: "放行",
                acl_action_drop: "拒绝",
                acl_dir_both: "↔ 双向",
                acl_dir_in: "↓ 入站",
                acl_dir_out: "↑ 出站",
                acl_proto_any: "任意",
                acl_proto_tcp: "TCP",
                acl_proto_udp: "UDP",
                acl_proto_icmp: "ICMP",
                acl_no_rules_short: "尚未定义自定义 ACL 规则（点击「添加规则」新建）",
                exit_node_title: "🌐 设置出口网关",
                exit_node_desc: "通过此节点路由公网出口流量",
                exit_enable_lbl: "开启 Exit Node 网关模式",
                exit_enable_desc: "允许将公网流量通过此节点转发",
                exit_nat_lbl: "开启 SNAT / Masquerade (源网络地址转换)",
                exit_nat_desc: "为出口流量提供源 IP 地址转换",
                exit_wan_lbl: "物理出口网卡 (WAN Interface)",
                section_subnet_title: "🌐 Subnet Router 局域网路由宣告与授权",
                section_subnet_desc: "宣告局域网子网并授权哪些 Peer 可以使用这些路由",
                adv_subnets_lbl: "宣告局域网 CIDR (每行一个)",
                accept_subnets_lbl: "允许接收远端节点的宣告子网路由",
                allowed_subnet_peers_lbl: "授权 Peer 清单 (* 代表信任所有, 每行一个)",
                section_acl_title: "🛡️ P2P 网状网络 ACL 防火墙规则编辑器",
                section_acl_desc: "按 Peer 粒度过滤流量的规则编辑器",
                add_rule_btn: "➕ 添加规则",
                enable_acl_lbl: "开启 ACL 防火墙引擎",
                acl_default_action_lbl: "未匹配流量默认策略",
                acl_flow_title: "规则优先匹配链 (从上至下执行):",
                acl_flow_hint_permit: "白名单放行列表 — 这些规则对命中流量执行 ALLOW，绕过默认 DROP 策略。",
                acl_flow_hint_block: "黑名单封禁列表 — 这些规则对命中流量执行 DENY，覆盖默认 ACCEPT 策略。",
                exit_node_badge: "🌐 Exit Node 出口",
                set_as_exit_btn: "🚀 设为出口网关",
                clear_exit_node_btn: "🛑 断开出口网关",
                active_exit_badge: "⚡ 当前出口网关",
                exit_connected: "🚀 已连接到出口网关 ",
                exit_disconnected: "🛑 已断开出口网关",
                peer_traffic_title: "节点实时收发速率与广播流量",
                topo_reset_layout: "📌 重置节点布局",
                topo_reset_zoom: "🔍 重置视角",
                bandwidth_chart_title: "📈 实时带宽波形 (发送 / 接收)",
                packet_rate_title: "📊 包速率分布 (发送 / 接收)",
                mesh_matrix_title: "🕸️ P2P 节点质量",
                matrix_src: "源节点",
                matrix_dst: "目标节点",
                matrix_rtt: "RTT 延迟",
                matrix_hops: "跳数 (Hops)",
                matrix_type: "链路类型",
                no_matrix: "暂无路由质量矩阵数据",
                subnet_routes_title: "🌐 子网路由",
                no_subnets: "未接收到授权的宣告子网路由",
                dup_ip_conflicts_title: "⚠️ 重复 IP / 子网冲突",
                no_dup_ip_conflicts: "未检测到重复 IP 或子网冲突",
                dup_winner: "胜出方",
                peer_meta_title: "📡 节点元数据与 Peek-Map 广播监视器",
                col_subnets: "宣告的子网路由",
                col_exit_egress: "Exit 出口节点模式",
                col_sync_channel: "元数据接收通道",
                col_last_sync: "最近接收时间",
                no_peer_metas: "暂未接收到来自 peek-map 或 P2P 的节点广播元数据",
                exit_client_card_title: "🚀 出口网关控制",
                exit_client_status_active: "⚡ 正在通过出口网关路由全部公网流量",
                exit_client_status_inactive: "未开启出口网关（正在使用本地默认网关）",
                exit_client_no_peers: "网内暂无提供 Exit Node 出口网关的在线节点",
                btn_connect_exit: "🚀 激活出口网关",
                exit_picker_hint: "选择上方节点作为本机出口",
                btn_disconnect_exit: "⏹️ 清除出口网关",
                btn_enable_subnet: "▶️ 启用",
                btn_disable_subnet: "🛑 停用",
                badge_subnet_disabled: "⏸️ 已停用",
                badge_subnet_pending: "⛔ 待授权",
                subnet_no_toggle: "不可路由",
                toast_subnet_enabled: "▶️ 子网路由 {cidr} 已实时启用",
                toast_subnet_disabled: "⏸️ 子网路由 {cidr} 已实时停用",
                acl_status_title: "🛡️ 防火墙",
                acl_open_desc: "防火墙处于完全开放模式 (所有 P2P 流量畅通)",
                acl_badge_open: "开放模式",
                acl_badge_active: "● 已启用",
                acl_open_hint: "在设置 → ACL 编辑器中启用 ACL 即可强制执行规则。",
                acl_label_rules: "规则",
                acl_label_default: "默认",
                acl_label_accepted: "已放行",
                acl_label_dropped: "已丢弃",
                acl_label_uptime: "运行时长",
                acl_label_top_rules: "命中最多的规则",
                acl_label_recent_drops: "最近丢弃",
                acl_label_default_action: "默认策略",
                acl_label_hits: "次",
                acl_label_more: "条未显示",
                acl_default_accept: "ACCEPT (放行)",
                acl_default_drop: "DROP (拒绝)",
                strategy_redundant: "双发冗余",
                strategy_fallback: "故障转移回退",
                log_level_debug: "详细调试",
                log_level_info: "标准信息",
                log_level_warn: "仅警告",
                log_level_error: "仅错误",
                obfs_fixed: "固定大小填充",
                obfs_block: "块倍数",
                obfs_random: "随机长度",
                obfs_dynamic: "可变范围",
                obfs_auto: "自动检测与切换",
                acl_editor_title: "🛡️ ACL 规则编辑器",
                acl_no_rules: "尚未定义自定义规则 —— 添加一条或选择模板。",
                acl_test_title: "🧪 ACL 规则测试器",
                acl_test_peer: "源 Peer ID",
                acl_test_dir: "方向",
                acl_test_proto: "协议",
                acl_test_dstip: "目的 IP",
                acl_test_dstport: "目的端口",
                acl_test_allow: "已放行",
                acl_test_deny: "已拒绝",
                acl_test_matched: "命中规则",
                acl_test_default: "无规则命中 —— 已应用默认策略",
                acl_template_lbl: "插入模板…",
                acl_comment_placeholder: "备注 / 描述",
                close_btn: "关闭",
                cancel_btn: "取消",
                save_btn: "保存并生效",
                save_success: "配置更新保存成功！",
                cfg_needs_restart: "⚠️ 禁用中继已变更，需重启 p2ptap 后生效。",
                save_failed: "保存失败: ",
                req_error: "保存网络请求错误: ",
                unnamed_node: "未命名节点",
                via_exit_node: "🚀 经出口节点",
                via_exit_node_hint: "流量经选中的出口节点网关转发出网",
                public_direct: "直连 (Public)",
                relayed_conn: "中转",
                relay_only: "仅中继",
                not_configured: "未配置",
                disc_addrs: "条已知 Multiaddr 通路",
                view_addr: "查看 Multiaddr",
                active_pathway: "当前活跃连接通路",
                active_pathway_unknown: "暂无活跃连接",
                best_reachable_pathway: "最佳可达候选（来自上次 multiaddr 探测）",
                probe_unverified: "未验证",
                logs_cleared: "系统日志已清空。",
                copied_toast: "📋 配置 JSON 已复制到剪贴板！",
                log_count: "{n} 条日志",
                log_listening: "正在监听实时日志事件...",
                multiaddr_placeholder: "/ip4/1.2.3.4/udp/4001/quic-v1/p2p/12D3KooW...",
                exit_wan_placeholder: "auto (自动检测物理出口网卡)",
                exit_status_title: "实时状态",
                exit_status_inactive: "当前无 Exit Node 隧道",
                exit_status_role_client: "客户端",
                exit_status_role_server: "服务端 (提供出口)",
                exit_status_role_both: "客户端 + 服务端",
                exit_status_routing_via: "出口流量经由此节点",
                exit_status_offering: "正为网格提供出口",
                exit_status_peer: "节点",
                exit_status_tap_ip: "TAP IP",
                exit_status_tap_ipv6: "TAP IPv6",
                subnets_placeholder: "例如 192.168.1.0/24",
                allowed_peers_placeholder: "例如 * 或 12D3KooW...",
                delete_rule: "🗑️ 删除",
                acl_peer_placeholder: "Peer ID 或 *",
                acl_cidr_placeholder: "目标 CIDR 或 *",
                acl_port_placeholder: "端口/范围",
                echo_test: "🧪 Echo 测试",
                echo_test_hint: "💡 点击任意 Echo 测试按钮以测量特定 Multiaddr 链路的延迟。",
                test_all: "🧪 全部探测",
                speedtest_btn: "⚡ 测速",
                test_echo: "⚡ Echo 测试",
                probing_text: "⏳ 探测中...",
                probe_result: "🧪 {reachable}/{total} 地址可达",
                probe_error: "🧪 探测错误",
                probing_echo: "🚀 正在通过 {addr} 探测 Echo 流...",
                probing_pathways_title: "🧪 正在探测 Multiaddr 通路...",
                probing_pathways_desc: "正在测试流可达性、RTT 及传输类型...",
                col_encryption: "加密",
                topo_legend_direct_fast: "● 直连 (<30ms)",
                topo_legend_direct_slow: "● 直连 (30-100ms)",
                topo_legend_relay: "● 中转中继（琥珀色）— 被中转的节点挂在它下方",
                topo_legend_flow: "💧 流量密度 = 实时收发速率（空闲链路不流动）",
                topo_badge_transit: "🌉 中轉交換機",
                topo_badge_exit_server: "🚪 出口服務端",
                topo_via: "經",
                topo_link_idle: "閒置",
                topo_summary_nodes: "節點",
                topo_summary_direct: "直連",
                topo_summary_relayed: "經中繼",
                topo_summary_relays: "中轉節點",
                topo_summary_thru: "網格吞吐",
                topo_summary_gw: "網關包",
                topo_summary_boots: "引導節點",
                topo_summary_static: "靜態節點",
                topo_summary_clusters: "叢集",
                topo_filter_remote: "跨叢集",
                topo_legend_boot: "● 引導節點 (紫色)",
                topo_legend_overlay: "◆ 覆蓋中繼 (長虛線)",
                topo_badge_boot: "引導",
                topo_badge_static: "靜態",
                topo_tt_role_boot: "引導節點",
                topo_tt_role_static: "靜態節點",
                topo_tt_cluster: "叢集:",
                topo_tt_boot_hops: "引導跳數:",
                topo_tt_transport_path: "傳輸路徑:",
                topo_tt_relay_hop: "中繼跳:",
                topo_tt_enc: "加密:",
                topo_tt_conn: "連線狀態:",
                topo_tt_jitter: "抖動:",
                topo_tt_loss: "丟包率:",
                topo_tt_version: "版本:",
                topo_tt_since: "已連線:",
                topo_tt_geo: "位置:",
                topo_tt_total: "累計 (發/收):",
                topo_tt_route_via: "路徑:",
                topo_tt_blackhole: "接收黑洞（去重偏移）",
                topo_tt_circuit_relay: "电路中继 v2",
                topo_tt_dedup_window: "去重窗口：",
                topo_tt_direct_link: "点对点直连",
                topo_tt_dup_drops: "重复丢弃：",
                topo_tt_healthy: "健康",
                topo_tt_ipv4: "虚拟 IPv4：",
                topo_tt_ipv6: "虚拟 IPv6：",
                topo_tt_link_integrity: "链路完整性：",
                topo_tt_live_rate: "实时速率：",
                topo_tt_local_host: "本地主机",
                topo_tt_optimal_route: "最优路由：",
                topo_tt_os_arch: "系统 / 架构：",
                topo_tt_peer_id: "节点 ID：",
                topo_tt_route: "路由：",
                topo_tt_route_gain: "路由增益：",
                topo_tt_rtt: "往返延迟：",
                topo_tt_seq: "序列号 (Tx/Rx)：",
                topo_tt_tap_ip: "PEER IP：",
                topo_tt_transit_relay: "中转中继",
                topo_tt_transport: "传输层：",
                topo_tt_uptime: "运行时长：",
            },
            "zh-TW": {
                default_node_name: "P2P TAP 虛擬專網節點",
                login_title: "🔐 P2P TAP 儀表板登入",
                login_subtitle: "此儀表板受保護，請輸入存取令牌以繼續。",
                login_token_label: "存取令牌",
                login_token_placeholder: "貼上啟動日誌或設定 (webui.auth_token) 中的令牌",
                login_btn: "登入",
                login_error: "令牌無效或請求失敗，請重試。",
                login_hint: "令牌會儲存在本機瀏覽器中，並作為 Bearer 請求標頭傳送。",
                speed_test: "⚡ P2P 測速",
                btn_add_static_peer: "➕ 新增 Static 節點",
                pcap_title: "🔬 封包擷取 (Packet Capture)",
                pcap_stopped: "已停止",
                pcap_running: "● 擷取中",
                pcap_start: "▶️ 開始",
                pcap_pause: "⏸️ 暫停",
                pcap_clear: "🗑️ 清除",
                pcap_autoscroll: "自動捲動",
                pcap_stream_live: "即時推送 (WebSocket)",
                pcap_stream_connecting: "正在連線…",
                pcap_stream_polling: "輪詢後備（即時推送不可用）",
                pcap_stream_off: "推送已中斷",
                pcap_stream_dropped: "用戶端處理緩慢，已丟幀",
                log_stream_live: "即時推送 (WebSocket)",
                log_stream_connecting: "正在連線…",
                log_stream_polling: "輪詢後備（即時推送不可用）",
                log_stream_off: "推送已中斷",
                log_stream_dropped: "用戶端處理緩慢，已丟日誌",
                pcap_desc: "擷取本機 TAP 虛擬網卡收發的原始乙太網路幀（含來源/目的 MAC、協定、IP、十六進位）。<span class=\"tx-tag\">tx</span> = 本機發出，<span class=\"rx-tag\">rx</span> = 本機收到。<span class=\"tx-tag\">點擊任意一列</span>可檢視完整詳情與原始幀十六進位。",
                pcap_empty: "尚無資料。點擊「開始」擷取本機 TAP 流量。",
                pcap_click_hint: "點擊檢視完整詳情",
                pcap_dup_repeat: "重複幀 — 與上一行完全相同 (mDNS / 多播重傳)",
                pcap_dup_repeat_row: "重複幀 — 與上一行 payload 完全相同。這是 mDNS / 多播重傳的正常現象，不是渲染重複。",
                pcap_modal_title: "🔬 封包詳情",
                pcap_modal_raw: "完整十六進位 (raw frame)",
                pcap_copy_hex: "📋 複製 Hex",
                pcap_dir_tx: "本機發出 (tx)",
                pcap_dir_rx: "本機收到 (rx)",
                pcap_f_seq: "序號",
                pcap_f_time: "時間",
                pcap_f_dir: "方向",
                pcap_f_srcmac: "來源 MAC",
                pcap_f_dstmac: "目的 MAC",
                pcap_f_etype: "EtherType",
                pcap_f_proto: "協定",
                pcap_f_vlan: "VLAN ID",
                pcap_f_l4proto: "L4 協定",
                pcap_f_srcip: "來源 IP",
                pcap_f_dstip: "目的 IP",
                pcap_f_srcport: "來源埠",
                pcap_f_dstport: "目的埠",
                pcap_f_tcpflags: "TCP 旗標",
                pcap_f_tcpseq: "TCP 序號",
                pcap_f_tcpwin: "TCP 視窗",
                pcap_f_dns: "DNS 查詢",
                pcap_f_sni: "TLS SNI",
                pcap_f_ttl: "TTL",
                pcap_f_arpop: "ARP 操作",
                pcap_f_arpsmac: "ARP 發送方 MAC",
                pcap_f_arpdmac: "ARP 目標 MAC",
                pcap_f_frompeer: "發出 Peer",
                pcap_f_topeer: "送達 Peer",
                pcap_f_len: "幀長度",
                pcap_f_info: "協定摘要",
                pcap_col_seq: "#",
                pcap_col_time: "時間",
                pcap_col_dir: "方向",
                pcap_col_srcmac: "來源 MAC",
                pcap_col_dstmac: "目的 MAC",
                pcap_col_etype: "類型",
                pcap_col_proto: "協定",
                pcap_col_srcip: "來源 IP",
                pcap_col_dstip: "目的 IP",
                pcap_col_ports: "埠",
                pcap_col_flags: "旗標",
                pcap_col_dns: "DNS",
                pcap_col_sni: "SNI",
                pcap_col_frompeer: "發出 Peer",
                pcap_col_topeer: "送達 Peer",
                pcap_col_len: "長度",
                pcap_col_info: "摘要",
                pcap_col_hex: "Hex(前64B)",
                share_config: "📲 分享與匯出",
                terminal_title: "📟 實時系統日誌主控台",
                auto_scroll: "📜 自動滾動: 開啟",
                auto_scroll_off: "📜 自動滾動: 關閉",
                clear_logs: "清空",
                pause_logs: "⏸️ 暫停",
                resume_logs: "▶️ 繼續",
                log_paused_badge: "⏸ 已暫停",
                copy_logs: "📋 複製",
                logs_copied: "📋 日誌已複製到剪貼簿！",
                logs_empty_copy: "尚無日誌可複製。",
                copy_failed: "複製失敗。",
                speedtest_title: "⚡ P2P 鏈路頻寬與延遲性能測速",
                select_target_peer: "選擇目標測速節點",
                mbps_label: "Mbps (P2P 傳輸吞吐速率)",
                rtt_avg: "平均延遲 RTT",
                jitter_lbl: "網路抖動 Jitter",
                quality_lbl: "鏈路質量",
                start_test_btn: "🚀 開始性能測速",
                share_title: "📲 配置匯出與二維碼分享",
                share_desc: "掃描二維碼或複製 JSON 設定檔以進行節點部署。",
                copy_json: "📋 複製 JSON",
                download_json: "💾 下載設定檔案",
                col_geo: "地理位置歸屬",
                col_conn_time: "已連接時長",
                col_last_active: "上次通訊時間",
                col_jitter_loss: "抖動 / 丟包率",
                col_status: "連線狀態",
                col_return_path: "回程狀態",
                conn_ok: "已連線",
                conn_relay_ok: "中繼正常",
                conn_connecting: "連線中",
                conn_proto_mismatch: "協定不符",
                conn_obf_failed: "解密失敗",
                conn_unreachable: "無法連線",
                return_ok: "回程正常",
                return_dead: "回程斷",
                return_idle: "回程未知",
                col_actions: "操作",
                topo_tx: "去程鏈路 (Tx ➔)",
                topo_rx: "回程鏈路 (Rx ⬅️)",
                topo_relay: "多跳中轉鏈路",
                peer_id_lbl: "節點ID",
                strategy_best_path: "最佳路徑",
                strategy_low_latency: "最低延遲",
                strategy_high_bandwidth: "高頻寬",
                search_placeholder: "搜尋…",
                prev_page: "‹ 上一頁",
                next_page: "下一頁 ›",
                per_page: "每頁",
                no_match: "無匹配",
                sys_health_title: "💻 系統與執行環境健康狀態",
                badge_active: "運行中",
                lbl_heap: "堆記憶體已用 / 總分配:",
                lbl_goroutines: "Goroutine 協程數:",
                lbl_gc_runs: "垃圾回收 (GC) 次數:",
                lbl_process_uptime: "進程在線時長:",
                lbl_heap_inuse: "堆記憶體實際佔用:",
                lbl_heap_objects: "堆上存活物件數:",
                lbl_stack_inuse: "協程堆疊總用量:",
                lbl_next_gc: "下次 GC 觸發:",
                lbl_last_gc_pause: "上次 GC 暫停:",
                lbl_gc_cpu: "GC 佔 CPU 比例:",
                lbl_gomaxprocs: "GOMAXPROCS:",
                lbl_cpu_cores: "CPU 核心數:",
                security_title: "🛡️ 安全與加密防護狀態",
                badge_protected: "受防護",
                lbl_psk_status: "PSK 預共享金鑰隔離:",
                lbl_traffic_obfs: "封包流量混淆:",
                lbl_id_fingerprint: "節點身份金鑰指紋:",
                lbl_autonat_reach: "AutoNAT 網路可達性:",
                lbl_per_peer_enc: "逐節點加密狀態:",
                sec_copy: "複製",
                sec_copied: "已複製",
                sec_peer_title: "節點加密詳情",
                sec_peer_id: "節點 ID",
                sec_peer_algo: "加密演算法",
                sec_peer_pfs: "前向保密 (PFS)",
                sec_yes: "是",
                sec_no: "否",
                sec_peer_tx_fp: "TX 金鑰指紋 (SHA-256 前 8 位)",
                sec_peer_rx_fp: "RX 金鑰指紋 (SHA-256 前 8 位)",
                sec_peer_pfs_eph: "臨時 ECDH 公鑰指紋",
                sec_peer_epoch_local: "本端握手 epoch",
                sec_peer_epoch_peer: "對端握手 epoch",
                sec_peer_copy: "複製",
                sec_peer_close: "關閉",
                sec_click_details: "點擊檢視完整資訊並複製指紋",
                no_peers_enc: "暫無已連線節點",
                protocol_dist_title: "🥧 虛擬網卡乙太幀協議分佈",
                public_unencrypted: "公共 Overlay (未加密)",
                encrypted_overlay: "加密 Overlay (Noise/PSK)",
                disabled: "未啟用",
                online: "線上 (2秒自動重新整理)",
                refresh: "🔄 手動重新整理",
                settings: "⚙️ 參數設定",
                tap_ipv4: "IPv4 位址",
                tap_ipv4_sub: "二層虛擬乙太網",
                tap_ipv6: "IPv6 位址",
                tap_ipv6_sub: "原生 IPv6 雙棧傳輸支援",
                tx_bytes: "傳送資料 (TX)",
                rx_bytes: "接收資料 (RX)",
                pkts_total: "封包總計: ",
                dedup_count: "冗餘過濾包 (Dedup)",
                dedup_sub: "多鏈路重複封包去重過濾",
                topology_mesh: "🕸️ 線上 P2P 拓撲星狀圖",
                topo_filter_label: "篩選：",
                topo_filter_all: "全部",
                topo_filter_direct: "直連",
                topo_filter_relayed: "經中繼",
                topo_click_hint: "單擊節點可查看詳情並高亮其到本機的路徑",
                topo_clear_sel: "關閉",
                ping_tool: "📡 P2P 鏈路網路診斷 (Ping & Traceroute)",
                troubleshoot_title: "🔧 P2P 通聯排查工具",
                troubleshoot_select_peer: "選擇要診斷的節點",
                troubleshoot_manual_input: "或手動輸入 Peer ID...",
                troubleshoot_run: "🔍 運行全面診斷",
                troubleshoot_running: "正在運行診斷...",
                troubleshoot_step1: "本地 TAP 接口檢查",
                troubleshoot_step2: "節點發現與連接狀態",
                troubleshoot_step3: "libp2p 流連通性探測",
                troubleshoot_step4: "傳輸層 Multiaddr 探測",
                linkcheck_title: "🔗 Multiaddr 鏈路檢測",
                linkcheck_desc: "傳輸層深度探測：multiaddr 合法 → DNS 解析 → TCP/QUIC → libp2p 傳輸 → Noise/TLS 握手 → Peer ID 匹配 → 連線成功。",
                linkcheck_input_ph: "輸入完整 P2P multiaddr，如 /ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...",
                linkcheck_btn: "🔗 執行鏈路檢測",
                linkcheck_inline: "🔗 檢測",
                linkcheck_inline_title: "對此 multiaddr 執行 7 段鏈路診斷",
                linkcheck_running: "正在執行鏈路檢測…",
                linkcheck_no_input: "請輸入要檢測的 multiaddr。",
                linkcheck_overall: "總體結論",
                linkcheck_peer: "目標 Peer",
                linkcheck_input: "測過的地址",
                linkcheck_transport: "傳輸層",
                linkcheck_resolved: "解析出的 IP",
                linkcheck_step1: "Multiaddr 合法",
                linkcheck_step2: "DNS 解析",
                linkcheck_step3: "TCP / QUIC 建立",
                linkcheck_step4: "libp2p 傳輸層",
                linkcheck_step5: "Noise / TLS 握手",
                linkcheck_step6: "Peer ID 匹配",
                linkcheck_step7: "libp2p 連線成功",
                troubleshoot_step5: "Overlay 路由路徑分析",
                troubleshoot_step6: "ARP/NDP 解析檢查",
                troubleshoot_step7: "ACL 防火牆與安全策略檢查",
                troubleshoot_pass: "通過",
                troubleshoot_fail: "失敗",
                troubleshoot_warn: "警告",
                troubleshoot_skip: "略過",
                troubleshoot_running: "執行中",
                troubleshoot_step8: "TAP 設備讀寫自檢",
                troubleshoot_step8_running: "正在執行 TAP 設備讀寫自檢…",
                troubleshoot_step8_unavailable: "本節點不支援 TAP 自檢。",
                troubleshoot_step8_stale_binary: "/api/tap/selftest 介面未回傳 JSON，目前執行的二進位檔很可能是舊版本，請重新編譯並重啟 p2ptap。",
                troubleshoot_step8_write_fail: "TAP 寫入路徑失敗。",
                troubleshoot_step8_device: "裝置",
                troubleshoot_step8_wintun_noloop: "無回環 —— Wintun 為 L3 隧道，屬正常現象",
                troubleshoot_step8_loopback_ok: "回環驗證通過",
                troubleshoot_step8_loopback_fail: "期望 TAP 回環，但未讀回任何幀",
                troubleshoot_step8_request_fail: "TAP 自檢請求失敗",
                troubleshoot_step9: "端到端 TAP 資料路徑轉發測試",
                troubleshoot_step9_running: "正在向對端 TAP IP 注入 TAP 幀（ICMP echo request）…",
                troubleshoot_step9_pass: "TAP 幀往返正常（ICMP echo request → 對端 → ICMP echo reply）。",
                troubleshoot_step9_sent: "已傳送",
                troubleshoot_step9_fail: "TAP 轉發測試失敗。",
                troubleshoot_step9_fail_detail: "TAP 轉發測試失敗 —— 即便 echo（第 7 步）通過，TAP 資料路徑仍然不通。",
                troubleshoot_step9_hint: "很可能是 overlay 單播/中繼路徑中斷，或對端 TAP 幀處理異常。請檢查中繼路徑與對端 TAP 裝置。",
                troubleshoot_step9_request_fail: "TAP 轉發測試請求失敗",
                common_ok: "正常",
                common_failed: "失敗",
                common_idle: "閒置",
                common_write: "寫入",
                common_read: "讀取",
                common_unknown_write_error: "未知寫入錯誤",
                troubleshoot_no_peer: "請選擇或輸入要診斷的節點",
                troubleshoot_idle: "選擇一個節點並點擊“運行全面診斷”開始排查通聯問題。",
                run_ping: "🚀 運行 Ping 測試",
                run_trace: "🔍 運行 P2P 路徑追蹤",
                ping_placeholder: "例如 10.0.0.2 或 12D3KooW...",
                active_peers: "⚡ 線上 P2P 節點",
                routes_table: "🛣️ 智慧 P2P Overlay 路由表",
                stat_total_routes: "已計算的路由總數",
                stat_relayed_routes: "智慧中轉加速路徑",
                stat_max_savings: "最大延遲優化節省",
                stat_mesh_health: "Overlay 網狀拓撲狀態",
                arp_table: "📋 虛擬網路 ARP / NDP 鄰居表",
                ip_analytics: "📊 24小時 IP 流量統計",
                mac_table: "🔀 虛擬交換機 MAC 位址表",
                no_routes: "路由表中暫無計算出的路徑",
                col_dest: "目標節點",
                col_hops: "跳數",
                col_optimal_path: "視覺化路由圖譜",
                col_total_rtt: "最優 RTT",
                col_direct_rtt: "直連 RTT",
                col_optimization: "智慧加速效果",
                col_route_status: "路由狀態",
                col_nodename: "節點名稱",
                col_role: "節點角色",
                col_osarch: "OS / 架構",
                col_tapip: "PEER IP",
                col_tap_ip: "虛擬 IP",
                col_nat: "NAT 狀態",
                col_peerid: "Peer ID",
                col_multiaddr: "網路 Multiaddr 位址",
                col_transport: "傳輸協定",
                col_uptime: "線上時長",
                col_rtt: "RTT 延遲",
                col_ip: "IP 位址",
                col_mac: "MAC 位址",
                col_rate: "即時速率",
                col_ip_attr: "所屬節點 / 歸屬",
                col_target_peer: "關聯目標 PeerID",
                col_type: "條目類型",
                col_tx_traffic: "傳送流量",
                col_rx_traffic: "接收流量",
                col_total_traffic: "總計流量",
                col_pkts: "封包計數",
                col_last_active: "最後活躍時間",
                ip_scope_local: "本機 TAP",
                ip_scope_peer: "組網節點",
                ip_scope_subnet: "路由子網",
                ip_scope_exit: "出口網關",
                ip_scope_special: "二層廣播/組播",
                ip_scope_wan: "公網 WAN",
                btn_disconnecting: "正在斷開...",
                topo_badge_peer: "組網節點",
                via: "經由",
                no_peers: "暫無線上連接的 Peer 節點",
                no_arps: "ARP 列表中暫無資料",
                no_ips: "暫無 IP 流量統計資料",
                no_macs: "MAC 位址表中暫無資料",
                col_mac_origin: "來源",
                mac_origin_self: "節點介面",
                mac_origin_lan: "LAN 轉發",
                mac_origin_self_tip: "該 Peer 自身虛擬 TAP 介面 MAC（本地管理位址，以 02:xx:… 開頭）。每個健康節點唯一一個。",
                mac_origin_lan_tip: "該 Peer 身後區域網路內的裝置（經橋接/轉發），並非 Peer 自身。出現多個表示此節點在轉發其 LAN 流量。",
                mac_lan_warn: "Peer {peer} 正在轉發 {n} 個 LAN 裝置流量——當該節點橋接/轉發其區域網路時屬正常現象，並非異常。",
                retrieving_metrics: "正在檢索節點鏈路資料...",
                modal_title: "⚙️ p2ptap 節點參數設定",
                node_name_lbl: "節點標識名稱",
                strategy_lbl: "傳輸策略",
                psk_lbl: "預共享金鑰 (PSK)",
                psk_placeholder: "留空為公開網路，設定金鑰後加密隔離",
                loglevel_lbl: "日誌級別",
                obfs_lbl: "混淆模式",
                obfs_fixed_size_lbl: "混淆固定包長",
                obfs_fixed_size_desc: "固定填充模式的目標 MTU（位元組）",
                bootstrap_lbl: "Bootstrap 中繼節點",
                section_identity: "節點身份",
                section_identity_desc: "此節點的名稱與加密設定",
                node_name_desc: "在儀表板中可讀的節點標識",
                psk_desc: "留空為公開網路，設定金鑰後加密隔離",
                section_transport: "傳輸與日誌",
                section_transport_desc: "路由策略與診斷日誌詳細程度",
                strategy_desc: "封包在 P2P 鏈路上的路由方式",
                loglevel_desc: "控制主控台日誌輸出的詳細程度",
                enable_mdns_lbl: "啟用 mDNS 區域網路節點發現",
                enable_mdns_desc: "透過 mDNS 自動發現同一區域網路內的節點（僅限本地網路）",
                cfg_disable_relay_lbl: "停用標準中繼 (排障診斷)",
                cfg_disable_relay_desc: "關閉 libp2p 標準 circuit-relay 客戶端/服務端、AutoRelay 與 DCUtR 打洞。需重啟生效。若開啟後某些慢節點無法連線，說明原先透過靜態中繼轉發。不影響 p2ptap 自有骨幹中繼。",
                section_obfs: "流量混淆",
                section_obfs_desc: "通過封包填充對抗 DPI 指紋識別",
                obfs_mode_desc: "P2P 資料幀的填充策略",
                section_bootstrap: "Bootstrap 節點",
                section_bootstrap_desc: "用於網路發現的初始中繼節點",
                bootstrap_placeholder: "每行輸入一個 multiaddr 位址",
                cfg_add_item: "➕ 新增",
                cfg_list_empty: "暫無條目。",
                drag_handle_tip: "拖曳以調整順序",
                drag_rule_tip: "拖曳以調整規則順序",
                move_up_tip: "上移",
                move_down_tip: "下移",
                acl_action_accept: "放行",
                acl_action_drop: "拒絕",
                acl_dir_both: "↔ 雙向",
                acl_dir_in: "↓ 入站",
                acl_dir_out: "↑ 出站",
                acl_proto_any: "任意",
                acl_proto_tcp: "TCP",
                acl_proto_udp: "UDP",
                acl_proto_icmp: "ICMP",
                acl_no_rules_short: "尚未定義自訂 ACL 規則（點擊「新增規則」建立）",
                exit_node_title: "🌐 設定出口網關",
                exit_enable_lbl: "開啟 Exit Node 閘道模式",
                exit_nat_lbl: "開啟 SNAT / Masquerade (源網路位址轉換)",
                exit_wan_lbl: "物理出口網卡 (WAN Interface)",
                exit_node_badge: "🌐 Exit Node 出口",
                set_as_exit_btn: "🚀 設為出口閘道",
                clear_exit_node_btn: "🛑 斷開出口閘道",
                active_exit_badge: "⚡ 當前出口閘道",
                exit_connected: "🚀 已連接到出口閘道 ",
                exit_disconnected: "🛑 已斷開出口閘道",
                peer_traffic_title: "節點實時收發速率與廣播流量",
                topo_reset_layout: "📌 重置節點佈局",
                topo_reset_zoom: "🔍 重置視角",
                bandwidth_chart_title: "📈 實時吞吐波形圖與流量歷史",
                mesh_matrix_title: "🕸️ P2P 節點質量",
                matrix_src: "源節點",
                matrix_dst: "目標節點",
                matrix_rtt: "RTT 延遲",
                matrix_hops: "跳數 (Hops)",
                matrix_type: "鏈路類型",
                no_matrix: "暫無路由質量矩陣數據",
                subnet_routes_title: "🌐 子網路由",
                no_subnets: "未接收到授權的宣告子網路由",
                dup_ip_conflicts_title: "⚠️ 重複 IP / 子網衝突",
                no_dup_ip_conflicts: "未偵測到重複 IP 或子網衝突",
                dup_winner: "勝出方",
                peer_meta_title: "📡 節點元數據與 Peek-Map 廣播監視器",
                col_subnets: "宣告的子網路由",
                col_exit_egress: "Exit 出口節點模式",
                col_sync_channel: "元數據接收通道",
                col_last_sync: "最近接收時間",
                no_peer_metas: "暫未接收到來自 peek-map 或 P2P 的節點廣播元數據",
                exit_client_card_title: "🚀 出口網關控制",
                exit_client_status_active: "⚡ 正在透過出口網關路由全部公網流量",
                exit_client_status_inactive: "未開啟出口網關（正在使用本地預設網關）",
                exit_client_no_peers: "網內暫無提供 Exit Node 出口網關的在線節點",
                btn_connect_exit: "🚀 激活出口網關",
                exit_picker_hint: "選擇上方節點作為本機出口",
                btn_disconnect_exit: "⏹️ 清除出口網關",
                btn_enable_subnet: "▶️ 啟用",
                btn_disable_subnet: "🛑 停用",
                badge_subnet_disabled: "⏸️ 已停用",
                badge_subnet_pending: "⛔ 待授權",
                subnet_no_toggle: "不可路由",
                toast_subnet_enabled: "▶️ 子網路由 {cidr} 已實時啟用",
                toast_subnet_disabled: "⏸️ 子網路由 {cidr} 已實時停用",
                acl_status_title: "🛡️ 防火牆",
                acl_open_desc: "防火牆處於完全開放模式 (所有 P2P 流量暢通)",
                acl_badge_open: "開放模式",
                acl_badge_active: "● 已啟用",
                acl_open_hint: "在設定 → ACL 編輯器中啟用 ACL 即可強制執行規則。",
                acl_label_rules: "規則",
                acl_label_default: "預設",
                acl_label_accepted: "已放行",
                acl_label_dropped: "已丟棄",
                acl_label_uptime: "執行時間",
                acl_label_top_rules: "命中最多的規則",
                acl_label_recent_drops: "最近丟棄",
                acl_label_default_action: "預設策略",
                acl_label_hits: "次",
                acl_label_more: "條未顯示",
                acl_default_accept: "ACCEPT (放行)",
                acl_default_drop: "DROP (拒絕)",
                strategy_redundant: "雙發冗餘",
                strategy_fallback: "故障轉移回退",
                log_level_debug: "詳細除錯",
                log_level_info: "標準資訊",
                log_level_warn: "僅警告",
                log_level_error: "僅錯誤",
                obfs_fixed: "固定大小填充",
                obfs_block: "塊倍數",
                obfs_random: "隨機長度",
                obfs_dynamic: "可變範圍",
                obfs_auto: "自動偵測與切換",
                acl_editor_title: "🛡️ ACL 規則編輯器",
                acl_no_rules: "尚未定義自訂規則 —— 新增一條或選擇模板。",
                acl_test_title: "🧪 ACL 規則測試器",
                acl_test_peer: "來源 Peer ID",
                acl_test_dir: "方向",
                acl_test_proto: "協定",
                acl_test_dstip: "目的 IP",
                acl_test_dstport: "目的連接埠",
                acl_test_allow: "已放行",
                acl_test_deny: "已拒絕",
                acl_test_matched: "命中規則",
                acl_test_default: "無規則命中 —— 已套用預設策略",
                acl_template_lbl: "插入模板…",
                acl_comment_placeholder: "備註 / 描述",
                close_btn: "關閉",
                cancel_btn: "取消",
                save_btn: "儲存並套用",
                save_success: "設定更新儲存成功！",
                cfg_needs_restart: "⚠️ 停用中繼已變更，需重新啟動 p2ptap 後生效。",
                save_failed: "儲存失敗: ",
                req_error: "儲存網路請求錯誤: ",
                unnamed_node: "未命名節點",
                via_exit_node: "🚀 經出口節點",
                via_exit_node_hint: "流量經選中的出口節點閘道轉發出網",
                public_direct: "直連 (Public)",
                relayed_conn: "中轉",
                relay_only: "僅中繼",
                not_configured: "未設定",
                log_count: "{n} 條日誌",
                log_listening: "正在監聽即時日誌事件...",
                multiaddr_placeholder: "/ip4/1.2.3.4/udp/4001/quic-v1/p2p/12D3KooW...",
                exit_wan_placeholder: "auto (自動偵測物理出口網卡)",
                exit_status_title: "即時狀態",
                exit_status_inactive: "目前無 Exit Node 隧道",
                exit_status_role_client: "客戶端",
                exit_status_role_server: "服務端 (提供出口)",
                exit_status_role_both: "客戶端 + 服務端",
                exit_status_routing_via: "出口流量經由此節點",
                exit_status_offering: "正為網格提供出口",
                exit_status_peer: "節點",
                exit_status_tap_ip: "TAP IP",
                exit_status_tap_ipv6: "TAP IPv6",
                subnets_placeholder: "例如 192.168.1.0/24",
                allowed_peers_placeholder: "例如 * 或 12D3KooW...",
                delete_rule: "🗑️ 刪除",
                acl_peer_placeholder: "Peer ID 或 *",
                acl_cidr_placeholder: "目標 CIDR 或 *",
                acl_port_placeholder: "連接埠/範圍",
                echo_test: "🧪 Echo 測試",
                echo_test_hint: "💡 點擊任意 Echo 測試按鈕以測量特定 Multiaddr 鏈路的延遲。",
                test_all: "🧪 全部探測",
                speedtest_btn: "⚡ 測速",
                test_echo: "⚡ Echo 測試",
                probing_text: "⏳ 探測中...",
                probe_result: "🧪 {reachable}/{total} 地址可達",
                probe_error: "🧪 探測錯誤",
                probing_echo: "🚀 正在透過 {addr} 探測 Echo 流...",
                probing_pathways_title: "🧪 正在探測 Multiaddr 通路...",
                probing_pathways_desc: "正在測試流可達性、RTT 及傳輸類型...",
                accept_subnets_lbl: "接受來自遠端節點發佈的子網路",
                acl_default_action_lbl: "未匹配流量的預設策略",
                acl_flow_title: "規則順序匹配流程：",
                acl_flow_hint_permit: "白名單放行清單 — 命中規則的流量會被 ALLOW，繞過預設 DROP 策略。",
                acl_flow_hint_block: "黑名單封鎖清單 — 命中規則的流量會被 DENY，覆寫預設 ACCEPT 策略。",
                active_pathway: "目前作用中的連線路徑",
                active_pathway_unknown: "目前無作用中連線",
                best_reachable_pathway: "最佳可達候選（來自上次 multiaddr 探測）",
                probe_unverified: "未驗證",
                add_rule_btn: "➕ 新增規則",
                adv_subnets_lbl: "發佈的子網路（CIDR，每行一筆）",
                allowed_subnet_peers_lbl: "允許的子網路節點 ID（* 表示信任全部，每行一筆）",
                btn_cancel: "取消",
                btn_close: "關閉",
                btn_test_save_peer: "➕ 測試並儲存永久節點",
                chosen_optimal: "🟢 已選擇最佳路徑",
                col_candidate_path: "候選路徑",
                col_inspector: "決策檢視器",
                col_rationale: "決策 / 拒絕理由",
                col_rtt_end: "端對端往返延遲",
                col_status: "狀態",
                col_tapmac: "TAP MAC",
                common_peer: "節點",
                common_rtt: "往返延遲",
                common_unknown: "未知錯誤",
                copied_toast: "📋 組態 JSON 已複製到剪貼簿！",
                desc_arp: "Layer-2 Address Resolution",
                desc_broadcast: "L2 廣播（含 ARP）",
                desc_gateway: "經由出口節點隧道傳輸",
                desc_icmp: "網路探測與保活",
                desc_multicast: "L2 多播（含 mDNS）",
                desc_seq_sync: "已同步節點 · 重播 / 視窗丟棄",
                desc_tcp: "可靠位元組流",
                desc_udp: "資料報傳輸",
                direct_optimal_desc: "直接實體延遲比任何候選多跳中繼路由更快",
                direct_optimal_title: "已選擇直接 P2P（最低延遲）",
                disc_addrs: "已發現位址路徑",
                enable_acl_lbl: "啟用 ACL 防火牆引擎",
                err_enter_multiaddr: "請輸入有效的 Multiaddr 字串",
                eval_table_title: "📊 Dijkstra 路由引擎 - 評估的候選路徑",
                exit_enable_desc: "透過此節點路由網際網路流量",
                exit_nat_desc: "對外流量的來源位址轉譯",
                exit_node_desc: "透過此節點的網際網路對外路由",
                inspect_btn: "🔍 檢視",
                inspector_title: "🧭 智慧路由決策檢視器",
                lbl_arp_broadcast: "ARP Broadcast Frames",
                lbl_broadcast_pkts: "廣播封包",
                lbl_gateway_pkts: "出口節點閘道封包",
                lbl_icmp_ping: "ICMP 回應（Ping）",
                lbl_multiaddr_str: "Multiaddr 字串",
                lbl_multicast_pkts: "多播封包",
                lbl_seq_sync: "序列同步與去重",
                lbl_tcp_packets: "TCP 串流封包",
                lbl_udp_packets: "UDP 傳輸封包",
                logs_cleared: "日誌已清除。",
                modal_add_static_desc: "請輸入包含目標 /p2p/<PEER_ID> 的完整 P2P Multiaddr。該位址將以 PermanentAddrTTL 永久註冊至 Peerstore 並自動連線。",
                modal_add_static_title: "➕ 新增永久靜態節點 Multiaddr",
                modal_diag_title: "⚡ 節點路徑診斷與效能測試",
                nat_fallback_desc: "在無法建立直接 P2P 連結時繞過對稱式 NAT 隔離",
                obfs_allow_switch_lbl: "允許自動模式切換",
                obfs_strict_key_lbl: "嚴格密鑰協商 (PFS)",
                obfs_strict_key_desc: "禁止回退到長期節點密鑰。每對 peer 必須用一次性 ECDH 臨時密鑰各自派生獨立的加密套件，否則該 peer 保持明文。強化每對密鑰隔離。",
                obfs_auto_title: "🤖 自動偵測設定",
                obfs_block_size_desc: "區塊模式的對齊粒度（位元組）",
                obfs_block_size_lbl: "區塊對齊大小",
                obfs_dynamic_desc: "可變大小幀的最小–最大範圍",
                obfs_dynamic_lbl: "動態大小範圍（位元組）",
                obfs_eval_interval_lbl: "評估間隔",
                obfs_jitter_desc: "Random jitter to break fixed-size patterns (0=off)",
                obfs_jitter_lbl: "抖動範圍（±位元組）",
                obfs_max_safe_desc: "PMTU safety threshold for obfuscated frames (bytes)",
                obfs_max_safe_lbl: "Max Safe Frame Size",
                obfs_threshold_lbl: "閾值",
                packet_rate_title: "📊 封包速率分佈（傳送 / 接收）",
                pcap_layer_frame: "幀",
                pcap_layer_tree: "協定解析",
                protocol_inspector_desc: "（第 2/3/4 層封包拆解與即時 PPS 統計）",
                protocol_inspector_title: "📊 即時流量與乙太網路協定檢視器",
                proto_channels_title: "📡 通訊協定通道與串流狀態監測",
                th_stream_proto: "協定 / 通道標識",
                th_stream_peer: "對端節點",
                th_stream_direction: "串流方向",
                th_stream_transport: "傳輸層與 Multiaddr 鏈路",
                th_stream_status: "狀態",
                search_streams_ph: "搜尋通訊流、協定、對端節點…",
                no_matching_streams: "未找到活躍通訊協定串流",
                no_channels: "未找到活躍協定通道",
                lbl_active_streams: "條活躍串流",
                lbl_streams: "條串流",
                dir_out: "出站 ↑",
                dir_in: "入站 ↓",
                stream_active: "活躍中",
                channel_status_active: "活躍",
                channel_status_running: "運行中",
                channel_status_idle: "閒置",
                channel_status_standby: "待命",
                channel_status_ready: "就緒",
                channel_status_open: "開放模式",
                category_sync: "同步",
                category_routing: "路由",
                category_pubsub: "發布訂閱",
                category_data: "數據傳輸",
                category_security: "安全隔離",
                category_transport: "傳輸層",
                category_diagnostics: "診斷",
                category_discovery: "發現",
                channel_seqsync_name: "序號同步 (SeqSync)",
                channel_seqsync_desc: "視窗去重與重放防護",
                channel_lsa_name: "LSA 鏈路狀態路由",
                channel_lsa_desc: "Dijkstra 最短路徑選路",
                channel_peekmap_name: "Peek-Map 全網拓撲廣播",
                channel_peekmap_desc: "引導拓撲發現與同步",
                channel_data_name: "虛擬 TAP 數據通路",
                channel_data_proto: "二層乙太網數據鏈路",
                channel_auth_name: "PSK Mesh 身分認證",
                channel_auth_desc: "PSK Mesh 網絡安全隔離",
                channel_dcutr_name: "DCUtR 自動打洞與中繼",
                channel_dcutr_desc: "NAT 直連打洞自動升級",
                cipher_lbl: "加密演算法",

                rejected: "❌ 已拒絕",
                relay_accel_active: "中繼加速作用中",
                relay_accel_desc: "Dijkstra 演算法計算的多跳路徑經由",
                relay_chosen_title: "已選擇智慧中繼",
                reset_view: "🎯 重設檢視",
                saved_latency: "已節省",
                section_acl_title: "🛡️ ZeroTier 風格 P2P 網狀 ACL 規則編輯器",
                section_acl_desc: "依 Peer 粒度過濾流量的規則編輯器",
                section_subnet_title: "🌐 子網路路由器與授權",
                section_subnet_desc: "公告子網路並授權哪些 Peer 可使用這些路由",
                target_node: "🎯 目標節點",
                toast_add_failed: "新增靜態節點失敗",
                toast_req_err: "請求錯誤",
                toast_static_added: "靜態節點已新增並永久註冊至 Peerstore！",
                toast_testing_adding: "正在測試並新增靜態節點",
                topo_self_node: "自身節點",
                topo_standalone: "🌐 獨立網狀節點（等待 P2P 節點連線中...）",
                topology_sub: "（拖曳節點重新擺放 | 滾輪縮放 | 雙擊執行 Ping）",
                topology_title: "🗺️ 拓撲星圖",
                unreachable: "不可達",
                view_addr: "檢視 Multiaddr",
                vs_direct: "相較於直接路徑",
                col_encryption: "加密",
                topo_legend_direct_fast: "● 直連 (<30ms)",
                topo_legend_direct_slow: "● 直連 (30-100ms)",
                topo_legend_relay: "● 中轉中繼（琥珀色）— 被中轉的節點掛在其下方",
                topo_legend_flow: "💧 流量密度 = 即時收發速率（閒置連結不流動）",
                topo_tt_blackhole: "接收黑洞（去重偏移）",
                topo_tt_circuit_relay: "電路中繼 v2",
                topo_tt_dedup_window: "去重視窗：",
                topo_tt_direct_link: "點對點直連",
                topo_tt_dup_drops: "重複丟棄：",
                topo_tt_healthy: "健康",
                topo_tt_ipv4: "虛擬 IPv4：",
                topo_tt_ipv6: "虛擬 IPv6：",
                topo_tt_link_integrity: "連結完整性：",
                topo_tt_live_rate: "即時速率：",
                topo_tt_local_host: "本機主機",
                topo_tt_optimal_route: "最優路由：",
                topo_tt_os_arch: "系統 / 架構：",
                topo_tt_peer_id: "節點 ID：",
                topo_tt_route: "路由：",
                topo_tt_route_gain: "路由增益：",
                topo_tt_rtt: "往返延遲：",
                topo_tt_seq: "序列號 (Tx/Rx)：",
                topo_tt_tap_ip: "PEER IP：",
                topo_tt_transit_relay: "中轉中繼",
                topo_tt_transport: "傳輸層：",
                topo_tt_uptime: "運行時長：",
                topo_badge_boot: "引導",
                topo_badge_exit_server: "🚪 出口伺服器",
                topo_badge_static: "靜態",
                topo_badge_transit: "🌉 中轉交換",
                topo_filter_remote: "跨叢集",
                topo_legend_boot: "● 引導節點 (紫色)",
                topo_legend_overlay: "◆ 覆蓋中繼 (長虛線)",
                topo_link_idle: "閒置",
                topo_summary_boots: "引導節點",
                topo_summary_clusters: "叢集",
                topo_summary_direct: "直連",
                topo_summary_gw: "網關封包",
                topo_summary_nodes: "節點",
                topo_summary_relayed: "中繼",
                topo_summary_relays: "中轉中繼",
                topo_summary_static: "靜態節點",
                topo_summary_thru: "Mesh 直通",
                topo_tt_boot_hops: "引導跳數:",
                topo_tt_cluster: "叢集:",
                topo_tt_conn: "連線狀態:",
                topo_tt_enc: "加密:",
                topo_tt_geo: "位置:",
                topo_tt_jitter: "抖動:",
                topo_tt_loss: "丟包率:",
                topo_tt_relay_hop: "中繼跳:",
                topo_tt_route_via: "路徑:",
                topo_tt_since: "已連線:",
                topo_tt_total: "累計 (發/收):",
                topo_tt_transport_path: "傳輸路徑:",
                topo_tt_version: "版本:",
                topo_via: "經由",
            },
            ja: {
                default_node_name: "P2P TAP 仮想VPNノード",
                login_title: "🔐 P2P TAP ダッシュボードログイン",
                login_subtitle: "このダッシュボードは保護されています。続行するにはアクセストークンを入力してください。",
                login_token_label: "アクセストークン",
                login_token_placeholder: "起動ログまたは設定 (webui.auth_token) のトークンを貼り付け",
                login_btn: "ログイン",
                login_error: "トークンが無効かリクエストに失敗しました。再試行してください。",
                login_hint: "トークンはブラウザにローカル保存され、Bearer ヘッダーとして送信されます。",
                speed_test: "⚡ P2P スピードテスト",
                btn_add_static_peer: "➕ Static ピアを追加",
                pcap_title: "🔬 パケットキャプチャ",
                pcap_stopped: "停止中",
                pcap_running: "● キャプチャ中",
                pcap_start: "▶️ 開始",
                pcap_pause: "⏸️ 一時停止",
                pcap_clear: "🗑️ クリア",
                pcap_autoscroll: "自動スクロール",
                pcap_stream_live: "ライブストリーム (WebSocket)",
                pcap_stream_connecting: "接続中…",
                pcap_stream_polling: "ポーリングにフォールバック",
                pcap_stream_off: "ストリーム切断",
                pcap_stream_dropped: "クライアント遅延による欠落フレーム",
                log_stream_live: "ライブストリーム (WebSocket)",
                log_stream_connecting: "接続中…",
                log_stream_polling: "ポーリングにフォールバック",
                log_stream_off: "ストリーム切断",
                log_stream_dropped: "クライアント遅延による欠落ログ",
                pcap_desc: "ローカル TAP 仮想 NIC で送受信される生イーサネットフレームをキャプチャします（送信元/宛先 MAC、プロトコル、IP、16進数を含む）。<span class=\"tx-tag\">tx</span> = ホストから送信、<span class=\"rx-tag\">rx</span> = 受信。<span class=\"tx-tag\">任意の行をクリック</span>すると詳細と生フレームの16進ダンプを表示します。",
                pcap_empty: "データがありません。「開始」をクリックしてローカル TAP トラフィックをキャプチャします。",
                pcap_click_hint: "クリックで詳細を表示",
                pcap_dup_repeat: "重複フレーム — 直前行と同一 (mDNS / マルチキャスト再送)",
                pcap_dup_repeat_row: "重複フレーム — 上の行と payload が完全一致。mDNS / マルチキャスト再送の正常動作であり、描画の重複ではありません。",
                pcap_modal_title: "🔬 パケット詳細",
                pcap_modal_raw: "完全な16進数 (raw frame)",
                pcap_copy_hex: "📋 Hex をコピー",
                pcap_dir_tx: "ホストから送信 (tx)",
                pcap_dir_rx: "受信 (rx)",
                pcap_f_seq: "シーケンス",
                pcap_f_time: "時刻",
                pcap_f_dir: "方向",
                pcap_f_srcmac: "送信元 MAC",
                pcap_f_dstmac: "宛先 MAC",
                pcap_f_etype: "EtherType",
                pcap_f_proto: "プロトコル",
                pcap_f_vlan: "VLAN ID",
                pcap_f_l4proto: "L4 プロトコル",
                pcap_f_srcip: "送信元 IP",
                pcap_f_dstip: "宛先 IP",
                pcap_f_srcport: "送信元ポート",
                pcap_f_dstport: "宛先ポート",
                pcap_f_tcpflags: "TCP フラグ",
                pcap_f_tcpseq: "TCP シーケンス",
                pcap_f_tcpwin: "TCP ウィンドウ",
                pcap_f_dns: "DNS クエリ",
                pcap_f_sni: "TLS SNI",
                pcap_f_ttl: "TTL",
                pcap_f_arpop: "ARP 操作",
                pcap_f_arpsmac: "ARP 送信元 MAC",
                pcap_f_arpdmac: "ARP 宛先 MAC",
                pcap_f_frompeer: "送信 Peer",
                pcap_f_topeer: "宛先 Peer",
                pcap_f_len: "フレーム長",
                pcap_f_info: "プロトコル概要",
                pcap_col_seq: "#",
                pcap_col_time: "時刻",
                pcap_col_dir: "方向",
                pcap_col_srcmac: "送信元 MAC",
                pcap_col_dstmac: "宛先 MAC",
                pcap_col_etype: "種別",
                pcap_col_proto: "プロトコル",
                pcap_col_srcip: "送信元 IP",
                pcap_col_dstip: "宛先 IP",
                pcap_col_ports: "ポート",
                pcap_col_flags: "フラグ",
                pcap_col_dns: "DNS",
                pcap_col_sni: "SNI",
                pcap_col_frompeer: "送信ピア",
                pcap_col_topeer: "受信ピア",
                pcap_col_len: "長さ",
                pcap_col_info: "概要",
                pcap_col_hex: "Hex (先頭64B)",
                share_config: "📲 共有とエクスポート",
                terminal_title: "📟 リアルタイムログコンソール",
                auto_scroll: "📜 自動スクロール: オン",
                auto_scroll_off: "📜 自動スクロール: オフ",
                clear_logs: "🗑️ ログ消去",
                pause_logs: "⏸️ 一時停止",
                resume_logs: "▶️ 再開",
                log_paused_badge: "⏸ 停止中",
                copy_logs: "📋 コピー",
                logs_copied: "📋 ログをクリップボードにコピーしました！",
                logs_empty_copy: "コピーするログがありません。",
                copy_failed: "コピーに失敗しました。",
                speedtest_title: "⚡ P2P 帯域幅＆遅延スピードテスト",
                select_target_peer: "テスト対象のピアを選択",
                mbps_label: "Mbps (P2P スループット)",
                rtt_avg: "平均 RTT",
                jitter_lbl: "ジッター",
                quality_lbl: "回線品質",
                start_test_btn: "🚀 テストを開始",
                share_title: "📲 設定エクスポートとQR共有",
                share_desc: "QRコードをスキャンするかJSON設定をエクスポートしてノードをデプロイします。",
                copy_json: "📋 JSONをコピー",
                download_json: "💾 ファイルをダウンロード",
                col_geo: "位置情報",
                col_conn_time: "接続時間",
                col_last_active: "最終アクティブ",
                col_jitter_loss: "ジッター / 損失率",
                col_status: "接続状態",
                col_return_path: "リターンパス",
                conn_ok: "接続済み",
                conn_relay_ok: "リレー正常",
                conn_connecting: "接続中",
                conn_proto_mismatch: "プロトコル不一致",
                conn_obf_failed: "復号失敗",
                conn_unreachable: "到達不可",
                return_ok: "リターン正常",
                return_dead: "リターン断",
                return_idle: "リターン不明",
                col_actions: "操作",
                topo_tx: "送信ルート (Tx ➔)",
                topo_rx: "返信ルート (Rx ⬅️)",
                topo_relay: "中継ホップ",
                peer_id_lbl: "ピアID",
                strategy_best_path: "最適パス",
                strategy_low_latency: "低遅延",
                strategy_high_bandwidth: "広帯域",
                search_placeholder: "検索…",
                prev_page: "‹ 前へ",
                next_page: "次へ ›",
                per_page: "1ページあたり",
                no_match: "一致なし",
                sys_health_title: "💻 システムとランタイムの健全性",
                badge_active: "アクティブ",
                lbl_heap: "ヒープ使用量 / システム:",
                lbl_goroutines: "Goroutine 数:",
                lbl_gc_runs: "GC 回数:",
                lbl_process_uptime: "プロセス稼働時間:",
                lbl_heap_inuse: "ヒープ実使用量:",
                lbl_heap_objects: "ヒープ上の生存オブジェクト:",
                lbl_stack_inuse: "Goroutine スタック使用量:",
                lbl_next_gc: "次回 GC 閾値:",
                lbl_last_gc_pause: "前回 GC 停止時間:",
                lbl_gc_cpu: "GC の CPU 使用率:",
                lbl_gomaxprocs: "GOMAXPROCS:",
                lbl_cpu_cores: "CPU コア数:",
                security_title: "🛡️ セキュリティ＆暗号化状態",
                badge_protected: "保護中",
                lbl_psk_status: "PSK メッシュ状態:",
                lbl_traffic_obfs: "トラフィック難読化:",
                lbl_id_fingerprint: "アイデンティティ指紋:",
                lbl_autonat_reach: "AutoNAT 到達可能性:",
                lbl_per_peer_enc: "ピアごとの暗号化:",
                sec_copy: "コピー",
                sec_copied: "コピーしました",
                sec_peer_title: "ピア暗号化の詳細",
                sec_peer_id: "ピア ID",
                sec_peer_algo: "暗号方式",
                sec_peer_pfs: "前方秘匿性 (PFS)",
                sec_yes: "はい",
                sec_no: "いいえ",
                sec_peer_tx_fp: "TX 鍵フィンガープリント (SHA-256 先頭 8 桁)",
                sec_peer_rx_fp: "RX 鍵フィンガープリント (SHA-256 先頭 8 桁)",
                sec_peer_pfs_eph: "一時 ECDH 公開鍵フィンガープリント",
                sec_peer_epoch_local: "ローカル ハンドシェイク epoch",
                sec_peer_epoch_peer: "ピア ハンドシェイク epoch",
                sec_peer_copy: "コピー",
                sec_peer_close: "閉じる",
                sec_click_details: "クリックで詳細表示・指紋コピー",
                no_peers_enc: "接続中のピアなし",
                protocol_dist_title: "🥧 プロトコルトラフィック分布",
                public_unencrypted: "パブリックメッシュ（暗号化なし）",
                encrypted_overlay: "暗号化メッシュ（Noise/PSK）",
                disabled: "無効",
                online: "オンライン (2秒自動更新)",
                refresh: "🔄 更新",
                settings: "⚙️ 設定",
                tap_ipv4: "仮想 IPv4 アドレス",
                tap_ipv4_sub: "レイヤー2 仮想イーサネット",
                tap_ipv6: "仮想 IPv6 アドレス",
                tap_ipv6_sub: "ネイティブ IPv6 デュアルスタック",
                tx_bytes: "送信データ (TX)",
                rx_bytes: "受信データ (RX)",
                pkts_total: "パケット合計: ",
                dedup_count: "重複排除パケット",
                dedup_sub: "マルチリンク重複パケットフィルタ",
                topology_mesh: "🕸️ リアルタイム P2P トポロジー",
                topo_filter_label: "フィルター：",
                topo_filter_all: "すべて",
                topo_filter_direct: "直接",
                topo_filter_relayed: "中継",
                topo_click_hint: "ノードをクリックすると詳細を表示し、自身へのパスを強調します",
                topo_clear_sel: "閉じる",
                ping_tool: "📡 P2P ネットワーク診断 (Ping & Traceroute)",
                run_ping: "🚀 Ping テストを実行",
                run_trace: "🔍 Traceroute 実行",
                ping_placeholder: "例: 10.0.0.2 または 12D3KooW...",
                active_peers: "⚡ アクティブ P2P ノード",
                routes_table: "🛣️ スマート P2P Overlay ルーティングテーブル",
                stat_total_routes: "計算済みルート総数",
                stat_relayed_routes: "中継加速パス",
                stat_max_savings: "最大レイテンシ削減",
                stat_mesh_health: "メッシュトポロジー状態",
                arp_table: "📋 仮想ネットワーク ARP / NDP テーブル",
                ip_analytics: "📊 24時間 IP トラフィック分析",
                mac_table: "🔀 仮想スイッチ MAC テーブル",
                no_routes: "計算されたルートはありません",
                col_dest: "宛先ノード",
                col_hops: "ホップ数",
                col_optimal_path: "ビジュアルルートパス",
                col_total_rtt: "最適 RTT",
                col_direct_rtt: "直接 RTT",
                col_optimization: "スマート加速",
                col_route_status: "ルート状態",
                col_nodename: "ノード名",
                col_role: "役割",
                col_osarch: "OS / アーキテクチャ",
                col_tapip: "PEER IP",
                col_tap_ip: "仮想 IP",
                col_nat: "NAT 状態",
                col_peerid: "Peer ID",
                col_multiaddr: "ネットワーク Multiaddr",
                col_transport: "トランスポート",
                col_uptime: "稼働時間",
                col_rtt: "RTT レイテンシ",
                col_ip: "IP アドレス",
                col_mac: "MAC アドレス",
                col_rate: "リアルタイム速度",
                col_ip_attr: "所属ノード / 属性",
                col_target_peer: "関連 PeerID",
                col_type: "タイプ",
                col_tx_traffic: "送信トラフィック",
                col_rx_traffic: "受信トラフィック",
                col_total_traffic: "合計トラフィック",
                col_pkts: "パケット数",
                col_last_active: "最終アクティブ",
                ip_scope_local: "ローカル TAP",
                ip_scope_peer: "メッシュピア",
                ip_scope_subnet: "ルーティングサブネット",
                ip_scope_exit: "出口ゲートウェイ",
                ip_scope_special: "L2 特殊",
                ip_scope_wan: "インターネット WAN",
                btn_disconnecting: "切断中...",
                topo_badge_peer: "メッシュピア",
                via: "経由",
                no_peers: "接続中の P2P ノードはありません",
                no_arps: "ARP テーブルにデータはありません",
                no_ips: "IP トラフィックデータはありません",
                no_macs: "MAC テーブルにデータはありません",
                col_mac_origin: "送信元",
                mac_origin_self: "自ノードIF",
                mac_origin_lan: "LAN 転送",
                mac_origin_self_tip: "このピア自身の仮想 TAP インターフェース MAC（ローカル管理アドレス、02:xx:… 始まり）。健全なピアは 1 つ。",
                mac_origin_lan_tip: "このピアの背後にある LAN 上のデバイス（ブリッジ/転送）。ピア自身ではありません。複数ある場合はピアが LAN トラフィックを中継しています。",
                mac_lan_warn: "ピア {peer} は {n} 台の LAN デバイスを転送中——ピアが LAN をブリッジ/転送する場合の正常な動作です（異常ではありません）。",
                retrieving_metrics: "ノードメトリクスを取得中...",
                modal_title: "⚙️ p2ptap ノード設定",
                node_name_lbl: "ノード名",
                strategy_lbl: "転送戦略",
                psk_lbl: "事前共有鍵 (PSK)",
                psk_placeholder: "空欄でパブリック、設定で暗号化分離",
                loglevel_lbl: "ログレベル",
                obfs_lbl: "難読化モード",
                obfs_fixed_size_lbl: "固定パケット長",
                obfs_fixed_size_desc: "固定パディングの目標MTU（バイト）",
                bootstrap_lbl: "Bootstrap リレーノード",
                section_identity: "ノード識別",
                section_identity_desc: "このノードの名前と暗号化設定",
                node_name_desc: "ダッシュボード上の人間が読める識別子",
                psk_desc: "空欄でパブリック、設定で暗号化分離",
                section_transport: "転送とログ",
                section_transport_desc: "ルーティング戦略と診断ログの詳細度",
                strategy_desc: "P2Pリンク上のパケットルーティング方式",
                loglevel_desc: "コンソール出力の詳細度を制御",
                enable_mdns_lbl: "mDNS LAN ノード検出を有効化",
                enable_mdns_desc: "mDNS で同一 LAN 内のノードを自動検出します（ローカルネットワークのみ）",
                cfg_disable_relay_lbl: "標準リレーを無効化 (診断用)",
                cfg_disable_relay_desc: "libp2pの標準circuit-relayクライアント/サービス、AutoRelayおよびDCUtRホールパンチングを無効化します（要再起動）。p2ptap独自のオーバーレイリレーには影響しません。",
                section_obfs: "トラフィック難読化",
                section_obfs_desc: "パケットパディングでDPIフィンガープリントを回避",
                obfs_mode_desc: "P2Pデータフレームのパディング戦略",
                section_bootstrap: "Bootstrap ノード",
                section_bootstrap_desc: "ネットワーク検出のための初期リレーノード",
                bootstrap_placeholder: "1行に1つのmultiaddrを入力",
                cfg_add_item: "➕ 追加",
                cfg_list_empty: "項目がありません。",
                drag_handle_tip: "ドラッグで並べ替え",
                drag_rule_tip: "ドラッグでルールを並べ替え",
                move_up_tip: "上へ移動",
                move_down_tip: "下へ移動",
                acl_action_accept: "許可",
                acl_action_drop: "拒否",
                acl_dir_both: "↔ 両方",
                acl_dir_in: "↓ 受信",
                acl_dir_out: "↑ 送信",
                acl_proto_any: "すべて",
                acl_proto_tcp: "TCP",
                acl_proto_udp: "UDP",
                acl_proto_icmp: "ICMP",
                acl_no_rules_short: "カスタム ACL ルールはまだありません（「ルールを追加」をクリックして作成）",
                cancel_btn: "キャンセル",
                save_btn: "保存して適用",
                save_success: "設定が正常に保存されました！",
                cfg_needs_restart: "⚠️ 中継無効の変更は、p2ptap の再起動後に反映されます。",
                save_failed: "保存に失敗しました: ",
                req_error: "保存リクエストエラー: ",
                unnamed_node: "名前なしノード",
                via_exit_node: "🚀 出口ノード経由",
                via_exit_node_hint: "選択した出口ノードゲートウェイ経由で外部へルーティング",
                public_direct: "直接 (Public)",
                relayed_conn: "リレー",
                relay_only: "リレー専用",
                not_configured: "未設定",
                log_count: "{n} ログ",
                log_listening: "リアルタイムログイベントを監視中...",
                multiaddr_placeholder: "/ip4/1.2.3.4/udp/4001/quic-v1/p2p/12D3KooW...",
                exit_wan_placeholder: "auto (物理出口NICを自動検出)",
                exit_status_title: "ライブステータス",
                exit_status_inactive: "Exit Node トンネルは非アクティブ",
                exit_status_role_client: "クライアント",
                exit_status_role_server: "サーバー (出口提供)",
                exit_status_role_both: "クライアント + サーバー",
                exit_status_routing_via: "トラフィックの出口経路",
                exit_status_offering: "メッシュへの出口を提供中",
                exit_status_peer: "ピア",
                exit_status_tap_ip: "TAP IP",
                exit_status_tap_ipv6: "TAP IPv6",
                subnets_placeholder: "例: 192.168.1.0/24",
                allowed_peers_placeholder: "例: * または 12D3KooW...",
                delete_rule: "🗑️ 削除",
                acl_peer_placeholder: "Peer ID または *",
                acl_cidr_placeholder: "ターゲット CIDR または *",
                acl_port_placeholder: "ポート/範囲",
                echo_test: "🧪 Echo テスト",
                echo_test_hint: "💡 特定の Multiaddr 経路のレイテンシを測定するには Echo Test ボタンをクリックしてください。",
                test_all: "🧪 全テスト",
                speedtest_btn: "⚡ 速度テスト",
                test_echo: "⚡ Echo テスト",
                probing_text: "⏳ プローブ中...",
                probe_result: "🧪 {reachable}/{total} アドレス到達可能",
                probe_error: "🧪 プローブエラー",
                probing_echo: "🚀 {addr} 経由で Echo ストリームをプローブ中...",
                probing_pathways_title: "🧪 Multiaddr 経路をプローブ中...",
                probing_pathways_desc: "ストリーム到達性、RTT、およびトランスポートタイプをテスト中...",
                accept_subnets_lbl: "リモートピアからアドバタイズされたサブネットを受け入れる",
                acl_default_action_lbl: "未一致トラフィックのデフォルトポリシー",
                acl_flow_title: "順次ルールフロー：",
                acl_flow_hint_permit: "許可例外リスト — デフォルト DROP ポリシーに反して、ルールに一致するトラフィックを ALLOW します。",
                acl_flow_hint_block: "拒否例外リスト — デフォルト ACCEPT ポリシーよりも、ルールに一致するトラフィックを DENY します。",
                acl_open_desc: "メッシュファイアウォールがオープン（全 P2P トラフィック許可）",
                acl_status_title: "🛡️ ファイアウォール",
                acl_badge_open: "オープンメッシュ",
                acl_badge_active: "● 有効",
                acl_open_hint: "設定 → ACL エディタで ACL を有効化するとルールが強制されます。",
                acl_label_rules: "ルール",
                acl_label_default: "デフォルト",
                acl_label_accepted: "許可",
                acl_label_dropped: "拒否",
                acl_label_uptime: "稼働時間",
                acl_label_top_rules: "最も多く一致したルール",
                acl_label_recent_drops: "最近の拒否",
                acl_label_default_action: "デフォルト",
                acl_label_hits: "回",
                acl_label_more: "件以上",
                acl_default_accept: "ACCEPT (許可)",
                acl_default_drop: "DROP (拒否)",
                strategy_redundant: "デュアル送信冗長",
                strategy_fallback: "フェイルオーバー",
                log_level_debug: "詳細デバッグ",
                log_level_info: "標準情報",
                log_level_warn: "警告のみ",
                log_level_error: "エラーのみ",
                obfs_fixed: "固定サイズパディング",
                obfs_block: "ブロック倍数",
                obfs_random: "ランダム長",
                obfs_dynamic: "可変範囲",
                obfs_auto: "自動検出と切替",
                acl_editor_title: "🛡️ ACL ルールエディタ",
                acl_no_rules: "カスタムルールはまだありません — 追加するかテンプレートを選択。",
                acl_test_title: "🧪 ACL ルールテスター",
                acl_test_peer: "送信元ピアID",
                acl_test_dir: "方向",
                acl_test_proto: "プロトコル",
                acl_test_dstip: "宛先IP",
                acl_test_dstport: "宛先ポート",
                acl_test_allow: "許可",
                acl_test_deny: "拒否",
                acl_test_matched: "一致したルール",
                acl_test_default: "ルール未一致 — デフォルトポリシーを適用",
                acl_template_lbl: "テンプレートを挿入…",
                acl_comment_placeholder: "コメント / 説明",
                close_btn: "閉じる",
                active_exit_badge: "⚡ アクティブゲートウェイ",
                active_pathway: "現在アクティブな接続パス",
                active_pathway_unknown: "アクティブな接続なし",
                best_reachable_pathway: "最良の到達可能候補（前回のマルチアドレスプローブから）",
                probe_unverified: "未検証",
                add_rule_btn: "➕ ルールを追加",
                adv_subnets_lbl: "アドバタイズされたサブネット（CIDR、1行に1つ）",
                allowed_subnet_peers_lbl: "許可されたサブネットピアID（* は全て信頼、1行に1つ）",
                badge_subnet_disabled: "⏸️ 無効",
                bandwidth_chart_title: "📈 ライブ帯域波形（送信 / 受信）",
                btn_cancel: "キャンセル",
                btn_close: "閉じる",
                btn_connect_exit: "🚀 出口ゲートウェイに接続",
                exit_picker_hint: "上のピアを選択して経由トラフィック",
                btn_disable_subnet: "🛑 無効化",
                btn_disconnect_exit: "⏹️ 出口を切断",
                btn_enable_subnet: "▶️ 有効化",
                btn_test_save_peer: "➕ テストして永続ピアを保存",
                chosen_optimal: "🟢 最適パスを選択",
                clear_exit_node_btn: "🛑 Disconnect Exit",
                col_candidate_path: "候補パス",
                col_exit_egress: "出口ノード出口トラフィック",
                col_inspector: "判定インスペクター",
                col_last_sync: "最終確認",
                col_rationale: "判定 / 拒否の理由",
                col_rtt_end: "エンドツーエンド RTT",
                col_status: "ステータス",
                col_subnets: "アドバタイズされたサブネット",
                col_sync_channel: "ディスカバリーチャネル",
                col_tapmac: "TAP MAC",
                common_failed: "失敗",
                common_idle: "アイドル",
                common_ok: "OK",
                common_peer: "ピア",
                common_read: "読込",
                common_rtt: "RTT",
                common_unknown: "不明なエラー",
                common_unknown_write_error: "不明な書込みエラー",
                common_write: "書込",
                copied_toast: "📋 設定 JSON をクリップボードにコピーしました！",
                desc_arp: "Layer-2 Address Resolution",
                desc_broadcast: "L2 ブロードキャスト（ARP 含む）",
                desc_gateway: "出口ノード経由のトンネル",
                desc_icmp: "ネットワークプローブとキープアライブ",
                desc_multicast: "L2 マルチキャスト（mDNS 含む）",
                desc_seq_sync: "同期済ピア · 再生 / ウィンドウ破棄",
                desc_tcp: "信頼性のあるバイトストリーム",
                desc_udp: "データグラム転送",
                direct_optimal_desc: "直接の物理遅延はどの候補マルチホップリレールートよりも速い",
                direct_optimal_title: "直接 P2P を選択（最低遅延）",
                disc_addrs: "発見されたアドレスパス",
                enable_acl_lbl: "ACL ファイアウォールエンジンを有効化",
                err_enter_multiaddr: "有効な Multiaddr 文字列を入力してください",
                eval_table_title: "📊 Dijkstra ルーティングエンジン - 評価済候補パス",
                exit_client_card_title: "🚀 出口ノードゲートウェイ制御",
                exit_client_no_peers: "現在出口ノード出口を提供しているオンラインピアはいません",
                exit_client_status_active: "⚡ 全インターネットトラフィックを出口ノード経由でルーティング",
                exit_client_status_inactive: "アクティブな出口ゲートウェイなし（ローカルデフォルトゲートウェイを使用）",
                exit_connected: "🚀 Exit gateway connected to ",
                exit_disconnected: "🛑 出口ゲートウェイが切断されました",
                exit_enable_desc: "このピア経由でインターネットトラフィックをルーティング",
                exit_enable_lbl: "出口ノードゲートウェイモードを有効化",
                exit_nat_desc: "送信トラフィックの送信元アドレス変換",
                exit_nat_lbl: "SNAT / マスカレード（送信元アドレス変換）を有効化",
                exit_node_badge: "🌐 出口ノード",
                exit_node_desc: "このノード経由のインターネット出口ルーティング",
                exit_node_title: "🌐 出口ノードゲートウェイ設定",
                exit_wan_lbl: "WAN 出口インターフェース（例: eth0 または auto）",
                inspect_btn: "🔍 検査",
                inspector_title: "🧭 スマートルーティング判定インスペクター",
                lbl_arp_broadcast: "ARP Broadcast Frames",
                lbl_broadcast_pkts: "ブロードキャストパケット",
                lbl_gateway_pkts: "出口ノードゲートウェイパケット",
                lbl_icmp_ping: "ICMP エコー（Ping）",
                lbl_multiaddr_str: "Multiaddr 文字列",
                lbl_multicast_pkts: "マルチキャストパケット",
                lbl_seq_sync: "シーケンス同期と重複排除",
                lbl_tcp_packets: "TCP ストリームパケット",
                lbl_udp_packets: "UDP 転送パケット",
                logs_cleared: "ログをクリアしました。",
                matrix_dst: "宛先ノード",
                matrix_hops: "ホップ数",
                matrix_rtt: "RTT 遅延",
                matrix_src: "送信元ノード",
                matrix_type: "リンク種別",
                mesh_matrix_title: "🕸️ メッシュ品質と遅延マトリックス",
                modal_add_static_desc: "ターゲット /p2p/<PEER_ID> を含む完全な P2P Multiaddr を入力してください。アドレスは PermanentAddrTTL で Peerstore に永続登録され自動接続されます。",
                modal_add_static_title: "➕ 永続静的ピア Multiaddr を追加",
                modal_diag_title: "⚡ ピアパス診断とベンチマーク",
                nat_fallback_desc: "直接 P2P リンクが到達不能な場合にSymmetric NAT 分離をバイパス",
                no_matrix: "マトリックスにピアルートがありません",
                no_peer_metas: "peek-map / P2P 経由でピアメタデータを受信していません",
                no_subnets: "アクティブなアドバタイズサブネットがありません",
                dup_ip_conflicts_title: "⚠️ IP / サブネットの重複",
                no_dup_ip_conflicts: "重複 IP / サブネット 競合は検出されませんでした",
                dup_winner: "勝者",
                obfs_allow_switch_lbl: "自動モード切替を許可",
                obfs_strict_key_lbl: "厳格な鍵ネゴシエーション (PFS)",
                obfs_strict_key_desc: "長期ノード鍵へのフォールバックを禁止します。各ピア対はワンショット ECDH 一時鍵で独自の暗号を派生させる必要があり、そうでなければそのピアは平文のままです。ピアごとの鍵分離を強化します。",
                obfs_auto_title: "🤖 自動検出設定",
                obfs_block_size_desc: "ブロックモードのアラインメント粒度（バイト）",
                obfs_block_size_lbl: "ブロックアラインメントサイズ",
                obfs_dynamic_desc: "可変サイズフレームの最小–最大範囲",
                obfs_dynamic_lbl: "動的サイズ範囲（バイト）",
                obfs_eval_interval_lbl: "評価間隔",
                obfs_jitter_desc: "Random jitter to break fixed-size patterns (0=off)",
                obfs_jitter_lbl: "ジッタ範囲（±バイト）",
                obfs_max_safe_desc: "PMTU safety threshold for obfuscated frames (bytes)",
                obfs_max_safe_lbl: "Max Safe Frame Size",
                obfs_threshold_lbl: "閾値",
                packet_rate_title: "📊 パケットレート分布（送信 / 受信）",
                pcap_layer_frame: "フレーム",
                pcap_layer_tree: "プロトコル解析",
                peer_meta_title: "📡 ピアメタデータと Peek-Map ディスカバリモニター",
                peer_traffic_title: "Peer Live Broadcasted Rate & Traffic",
                protocol_inspector_desc: "（レイヤ 2/3/4 パケット内訳とライブ PPS 統計）",
                protocol_inspector_title: "📊 ライブトラフィックとイーサネットプロトコルインスペクター",
                proto_channels_title: "📡 プロトコルストリームとチャネル状態監視",
                th_stream_proto: "プロトコル / チャネル",
                th_stream_peer: "対向ピア",
                th_stream_direction: "方向",
                th_stream_transport: "トランスポート & Multiaddr",
                th_stream_status: "状態",
                search_streams_ph: "ストリーム、プロトコル、ピアを検索…",
                no_matching_streams: "アクティブなプロトコルストリームが見つかりません",
                no_channels: "アクティブなチャネルがありません",
                lbl_active_streams: "ストリーム",
                lbl_streams: "ストリーム",
                dir_out: "送信 ↑",
                dir_in: "受信 ↓",
                stream_active: "アクティブ",
                channel_status_active: "アクティブ",
                channel_status_running: "実行中",
                channel_status_idle: "アイドル",
                channel_status_standby: "スタンバイ",
                channel_status_ready: "レディ",
                channel_status_open: "オープンモード",
                category_sync: "同期",
                category_routing: "ルーティング",
                category_pubsub: "PubSub",
                category_data: "データ転送",
                category_security: "セキュリティ",
                category_transport: "トランスポート",
                category_diagnostics: "診断",
                category_discovery: "検出",
                channel_seqsync_name: "シーケンス同期 (SeqSync)",
                channel_seqsync_desc: "ウィンドウ重複排除とリプレイ保護",
                channel_lsa_name: "LSA メッシュルーティング",
                channel_lsa_desc: "Dijkstra 最短パス選路",
                channel_peekmap_name: "Peek-Map トポロジブロードキャスト",
                channel_peekmap_desc: "ブートストラップトポロジ同期",
                channel_data_name: "仮想 TAP データパス",
                channel_data_proto: "レイヤ 2 イーサネットオーバーレイ",
                channel_auth_name: "PSK メッシュ認証",
                channel_auth_desc: "PSK メッシュネットワーク分離",
                channel_dcutr_name: "DCUtR ホールパンチ & リレー",
                channel_dcutr_desc: "直接接続への自動アップグレード",
                cipher_lbl: "暗号化アルゴリズム",

                rejected: "❌ 拒否",
                relay_accel_active: "リレー高速化アクティブ",
                relay_accel_desc: "Dijkstra アルゴリズムが計算したマルチホップパス経由",
                relay_chosen_title: "スマートリレーを選択",
                reset_view: "🎯 ビューをリセット",
                saved_latency: "削減",
                section_acl_title: "🛡️ ZeroTier スタイル P2P メッシュ ACL ルールエディター",
                section_acl_desc: "ピア単位でトラフィックをフィルタリングするルール",
                section_subnet_title: "🌐 サブネットルーターと認可",
                section_subnet_desc: "サブネットを advertise し、利用可能な Peer を認可",
                set_as_exit_btn: "🚀 Set as Gateway",
                subnet_no_toggle: "ルーティング不可",
                subnet_routes_title: "🌐 サブネットルート",
                badge_subnet_pending: "⛔ 認可待ち",
                target_node: "🎯 ターゲットノード",
                toast_add_failed: "静的ピアの追加に失敗",
                toast_req_err: "リクエストエラー",
                toast_static_added: "静的ピアを追加し Peerstore に永続登録しました！",
                toast_subnet_disabled: "⏸️ サブネットルート {cidr} をリアルタイムで無効化",
                toast_subnet_enabled: "▶️ サブネットルート {cidr} をリアルタイムで有効化",
                toast_testing_adding: "静的ピアをテストして追加中",
                topo_reset_layout: "📌 Reset Layout",
                topo_reset_zoom: "🔍 Reset View",
                topo_self_node: "自身のノード",
                topo_standalone: "🌐 スタンドアロンメッシュノード（P2P ピア接続待ち...）",
                topology_sub: "（ノードをドラッグして移動 | スクロールでズーム | ダブルクリックで Ping）",
                topology_title: "🗺️ トポロジースター図",
                troubleshoot_fail: "失敗",
                troubleshoot_idle: "ピアを選択し「完全診断を実行」をクリックして接続問題のトラブルシューティングを開始してください。",
                troubleshoot_manual_input: "またはピアIDを手動で入力...",
                troubleshoot_no_peer: "診断するピアを選択または入力してください",
                troubleshoot_pass: "合格",
                troubleshoot_run: "🔍 完全診断を実行",
                troubleshoot_running: "実行中",
                troubleshoot_select_peer: "診断するピアを選択",
                troubleshoot_skip: "スキップ",
                troubleshoot_step1: "ローカル TAP インターフェース確認",
                troubleshoot_step2: "ピアディスカバリーと接続状態",
                troubleshoot_step3: "libp2p ストリーム接続プローブ",
                troubleshoot_step4: "トランスポートレベル Multiaddr プローブ",
                linkcheck_title: "🔗 Multiaddr リンクチェック",
                linkcheck_desc: "トランスポート層の詳細診断：multiaddr 妥当性 → DNS 解決 → TCP/QUIC → libp2p トランスポート → Noise/TLS ハンドシェイク → Peer ID 照合 → 接続。",
                linkcheck_input_ph: "完全な P2P multiaddr を入力、例 /ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...",
                linkcheck_btn: "🔗 リンクチェック実行",
                linkcheck_inline: "🔗 検査",
                linkcheck_inline_title: "この multiaddr の 7 段階リンク診断を実行",
                linkcheck_running: "リンクチェック実行中…",
                linkcheck_no_input: "チェックする multiaddr を入力してください。",
                linkcheck_overall: "総合結果",
                linkcheck_peer: "対象 Peer",
                linkcheck_input: "テスト対象アドレス",
                linkcheck_transport: "トランスポート",
                linkcheck_resolved: "解決済み IP",
                linkcheck_step1: "Multiaddr 妥当性",
                linkcheck_step2: "DNS 解決",
                linkcheck_step3: "TCP / QUIC 確立",
                linkcheck_step4: "libp2p トランスポート",
                linkcheck_step5: "Noise / TLS ハンドシェイク",
                linkcheck_step6: "Peer ID 照合",
                linkcheck_step7: "libp2p 接続成功",
                troubleshoot_step5: "オーバーレイルーティングパス解析",
                troubleshoot_step6: "ARP/NDP 解決確認",
                troubleshoot_step7: "ACL とセキュリティポリシー確認",
                troubleshoot_step8: "TAP デバイス読書込自己テスト",
                troubleshoot_step8_device: "デバイス",
                troubleshoot_step8_loopback_fail: "TAP ループバックを期待したがフレームが読み返されなかった",
                troubleshoot_step8_loopback_ok: "ループバックを確認",
                troubleshoot_step8_request_fail: "TAP 自己テストリクエストに失敗",
                troubleshoot_step8_running: "TAP デバイスの読書込自己テストを実行中…",
                troubleshoot_step8_stale_binary: "/api/tap/selftest エンドポイントが JSON で応答しませんでした。実行中のバイナリが古い可能性があります — p2ptap を再ビルドして再起動してください。",
                troubleshoot_step8_unavailable: "このノードでは TAP 自己テストは利用できません。",
                troubleshoot_step8_wintun_noloop: "ループバックなし — Wintun は L3 トンネルであり想定通り",
                troubleshoot_step8_write_fail: "TAP 書込パスが失敗。",
                troubleshoot_step9: "エンドツーエンド TAP データパス転送テスト",
                troubleshoot_step9_fail: "TAP 転送テストが失敗しました。",
                troubleshoot_step9_fail_detail: "TAP 転送テストが失敗 — エコー（ステップ7）は通過したにもかかわらず TAP データパスが壊れています。",
                troubleshoot_step9_hint: "オーバーレーのユニキャスト / リレーパスが壊れているか、ピア側の TAP フレーム処理に問題がある可能性があります。リレーパスとピアの TAP デバイスを確認してください。",
                troubleshoot_step9_pass: "TAP フレームの往復は正常（ICMP エコー要求 → ピア → ICMP エコー応答）。",
                troubleshoot_step9_request_fail: "TAP 転送テストリクエストに失敗",
                troubleshoot_step9_running: "オーバーレーに TAP フレーム（ICMP エコー要求）をピアの TAP IP へ注入中…",
                troubleshoot_step9_sent: "送信済",
                troubleshoot_title: "🔧 P2P 接続トラブルシューター",
                troubleshoot_warn: "警告",
                unreachable: "到達不能",
                view_addr: "Multiaddr を表示",
                vs_direct: "直接パスと比較して",
                col_encryption: "暗号化",
                topo_legend_direct_fast: "● 直接接続 (<30ms)",
                topo_legend_direct_slow: "● 直接接続 (30-100ms)",
                topo_legend_relay: "● 中継リレー（琥珀色）— 中継されるピアはその下に配置",
                topo_legend_flow: "💧 流量密度 = 実際の送受信レート（アイドル回線は流れない）",
                topo_badge_transit: "🌉 中継スイッチ",
                topo_badge_exit_server: "🚪 出口サーバー",
                topo_via: "経由",
                topo_link_idle: "アイドル",
                topo_summary_nodes: "ノード",
                topo_summary_direct: "直接",
                topo_summary_relayed: "中継",
                topo_summary_relays: "中継ノード",
                topo_summary_thru: "メッシュスループット",
                topo_summary_gw: "ゲートウェイPkt",
                topo_summary_boots: "ブートストラップ",
                topo_summary_static: "静的ピア",
                topo_summary_clusters: "クラスター",
                topo_filter_remote: "クラスター間",
                topo_legend_boot: "● ブートストラップノード (紫)",
                topo_legend_overlay: "◆ オーバーレイリレー (長い破線)",
                topo_badge_boot: "ブート",
                topo_badge_static: "静的",
                topo_tt_role_boot: "ブートストラップノード",
                topo_tt_role_static: "静的ピア",
                topo_tt_cluster: "クラスター:",
                topo_tt_boot_hops: "ブートホップ:",
                topo_tt_transport_path: "転送パス:",
                topo_tt_relay_hop: "リレーホップ:",
                topo_tt_enc: "暗号化:",
                topo_tt_conn: "接続状態:",
                topo_tt_jitter: "ジッター:",
                topo_tt_loss: "損失率:",
                topo_tt_version: "バージョン:",
                topo_tt_since: "接続:",
                topo_tt_geo: "地域:",
                topo_tt_total: "合計 (送/受):",
                topo_tt_route_via: "経路:",
                topo_tt_blackhole: "受信ブラックホール（重複排除のズレ）",
                topo_tt_circuit_relay: "回線リレー v2",
                topo_tt_dedup_window: "重複排除ウィンドウ：",
                topo_tt_direct_link: "P2P 直接リンク",
                topo_tt_dup_drops: "重複ドロップ：",
                topo_tt_healthy: "正常",
                topo_tt_ipv4: "仮想 IPv4：",
                topo_tt_ipv6: "仮想 IPv6：",
                topo_tt_link_integrity: "リンク整合性：",
                topo_tt_live_rate: "ライブレート：",
                topo_tt_local_host: "ローカルホスト",
                topo_tt_optimal_route: "最適ルート：",
                topo_tt_os_arch: "OS / アーキテクチャ：",
                topo_tt_peer_id: "ピア ID：",
                topo_tt_route: "ルート：",
                topo_tt_route_gain: "ルートゲイン：",
                topo_tt_rtt: "往復遅延：",
                topo_tt_seq: "シーケンス (Tx/Rx)：",
                topo_tt_tap_ip: "PEER IP：",
                topo_tt_transit_relay: "中継リレー",
                topo_tt_transport: "トランスポート：",
                topo_tt_uptime: "稼働時間：",
            },
            "de": {
                default_node_name: "P2P TAP VPN-Knoten",
                login_title: "🔐 P2P TAP Dashboard-Anmeldung",
                login_subtitle: "Dieses Dashboard ist geschützt. Geben Sie Ihr Zugriffstoken ein, um fortzufahren.",
                login_token_label: "Zugriffstoken",
                login_token_placeholder: "Token aus Startprotokoll oder Config (webui.auth_token) einfügen",
                login_btn: "Anmelden",
                login_error: "Ungültiges Token oder Anfrage fehlgeschlagen. Bitte erneut versuchen.",
                login_hint: "Das Token wird lokal im Browser gespeichert und als Bearer-Header gesendet.",
                speed_test: "⚡ P2P-Geschwindigkeitstest",
                btn_add_static_peer: "➕ Statischen Peer hinzufügen",
                pcap_title: "🔬 Paketmitschnitt",
                pcap_stopped: "Gestoppt",
                pcap_running: "● Erfasse",
                pcap_start: "▶️ Start",
                pcap_pause: "⏸️ Pause",
                pcap_clear: "🗑️ Leeren",
                pcap_autoscroll: "Auto-Scroll",
                pcap_stream_live: "Live-Stream (WebSocket)",
                pcap_stream_connecting: "Verbinde…",
                pcap_stream_polling: "Polling-Fallback (Stream nicht verfügbar)",
                pcap_stream_off: "Stream getrennt",
                pcap_stream_dropped: "Frames vom Client verworfen",
                log_stream_live: "Live-Stream (WebSocket)",
                log_stream_connecting: "Verbinde…",
                log_stream_polling: "Polling-Fallback (Stream nicht verfügbar)",
                log_stream_off: "Stream getrennt",
                log_stream_dropped: "Logs vom Client verworfen",
                pcap_desc: "Erfasst rohe Ethernet-Frames, die über die lokale TAP-Virtual-NIC gesendet/empfangen werden (inkl. Quell/Ziel-MAC, Protokoll, IP, Hex). <span class=\"tx-tag\">tx</span> = vom Host gesendet, <span class=\"rx-tag\">rx</span> = empfangen. <span class=\"tx-tag\">Zeile anklicken</span> für vollständige Details und Hex-Dump.",
                pcap_empty: "Noch keine Daten. Klicke \"Start\", um lokalen TAP-Verkehr zu erfassen.",
                pcap_click_hint: "Klicken für vollständige Details",
                pcap_dup_repeat: "Wiederholtes Frame — identisch zur vorherigen Zeile (mDNS / Multicast-Re-Transmit)",
                pcap_dup_repeat_row: "Wiederholtes Frame — gleicher Payload wie die vorherige Zeile. Das ist normales mDNS-/Multicast-Verhalten, kein Render-Duplikat.",
                pcap_modal_title: "🔬 Paketdetails",
                pcap_modal_raw: "Vollständiges Hex (raw frame)",
                pcap_copy_hex: "📋 Hex kopieren",
                pcap_dir_tx: "Vom Host gesendet (tx)",
                pcap_dir_rx: "Empfangen (rx)",
                pcap_f_seq: "Seq",
                pcap_f_time: "Zeit",
                pcap_f_dir: "Richtung",
                pcap_f_srcmac: "Quell-MAC",
                pcap_f_dstmac: "Ziel-MAC",
                pcap_f_etype: "EtherType",
                pcap_f_proto: "Protokoll",
                pcap_f_vlan: "VLAN ID",
                pcap_f_l4proto: "L4-Protokoll",
                pcap_f_srcip: "Quell-IP",
                pcap_f_dstip: "Ziel-IP",
                pcap_f_srcport: "Quell-Port",
                pcap_f_dstport: "Ziel-Port",
                pcap_f_tcpflags: "TCP-Flags",
                pcap_f_tcpseq: "TCP-Sequenz",
                pcap_f_tcpwin: "TCP-Fenster",
                pcap_f_dns: "DNS-Abfrage",
                pcap_f_sni: "TLS SNI",
                pcap_f_ttl: "TTL",
                pcap_f_arpop: "ARP-Op",
                pcap_f_arpsmac: "ARP-Absender-MAC",
                pcap_f_arpdmac: "ARP-Ziel-MAC",
                pcap_f_frompeer: "Von Peer",
                pcap_f_topeer: "An Peer",
                pcap_f_len: "Frame-Länge",
                pcap_f_info: "Protokoll-Zusammenfassung",
                pcap_col_seq: "#",
                pcap_col_time: "Zeit",
                pcap_col_dir: "Ri.",
                pcap_col_srcmac: "Quell-MAC",
                pcap_col_dstmac: "Ziel-MAC",
                pcap_col_etype: "Typ",
                pcap_col_proto: "Proto",
                pcap_col_srcip: "Quell-IP",
                pcap_col_dstip: "Ziel-IP",
                pcap_col_ports: "Ports",
                pcap_col_flags: "Flags",
                pcap_col_dns: "DNS",
                pcap_col_sni: "SNI",
                pcap_col_frompeer: "Von Peer",
                pcap_col_topeer: "An Peer",
                pcap_col_len: "Länge",
                pcap_col_info: "Info",
                pcap_col_hex: "Hex (erste 64B)",
                share_config: "📲 Teilen & Exportieren",
                terminal_title: "📟 Live-Systemprotokolle",
                auto_scroll: "📜 Auto-Scroll: AN",
                auto_scroll_off: "📜 Auto-Scroll: AUS",
                clear_logs: "🗑️ Leeren",
                pause_logs: "⏸️ Pause",
                resume_logs: "▶️ Fortsetzen",
                log_paused_badge: "⏸ Pausiert",
                copy_logs: "📋 Kopieren",
                logs_copied: "📋 Logs in Zwischenablage kopiert!",
                logs_empty_copy: "Nichts zu kopieren.",
                copy_failed: "Kopieren fehlgeschlagen.",
                speedtest_title: "⚡ P2P Bandbreite & Latenz Test",
                select_target_peer: "Ziel-Knoten auswählen",
                mbps_label: "Mbps (P2P-Durchsatz)",
                rtt_avg: "Durchschnittl. RTT",
                jitter_lbl: "Jitter",
                quality_lbl: "Qualität",
                start_test_btn: "🚀 Benchmark starten",
                share_title: "📲 Konfiguration teilen & exportieren",
                share_desc: "Scannen Sie den QR-Code oder exportieren Sie die Konfigurations-JSON.",
                copy_json: "📋 JSON kopieren",
                download_json: "💾 Datei herunterladen",
                col_geo: "Standort",
                col_conn_time: "Verbindungszeit",
                col_last_active: "Zuletzt aktiv",
                col_jitter_loss: "Jitter / Verlust",
                col_status: "Verbindungsstatus",
                col_return_path: "Rückweg",
                conn_ok: "Verbunden",
                conn_relay_ok: "Relay OK",
                conn_connecting: "Verbinde",
                conn_proto_mismatch: "Protokoll-Fehler",
                conn_obf_failed: "Entschlüsseln fehlgeschlagen",
                conn_unreachable: "Nicht erreichbar",
                return_ok: "Rückweg OK",
                return_dead: "Rückweg unterbrochen",
                return_idle: "Rückweg unbekannt",
                col_actions: "Aktionen",
                topo_tx: "Hingang (Tx ➔)",
                topo_rx: "Rückgang (Rx ⬅️)",
                topo_relay: "Relais-Kette",
                peer_id_lbl: "Peer-ID",
                strategy_best_path: "BESTER WEG",
                strategy_low_latency: "NIEDRIGE LATENZ",
                strategy_high_bandwidth: "HOHE BANDBREITE",
                search_placeholder: "Suchen…",
                prev_page: "‹ Zurück",
                next_page: "Weiter ›",
                per_page: "Pro Seite",
                no_match: "Keine Treffer",
                sys_health_title: "💻 System- und Runtime-Zustand",
                badge_active: "Aktiv",
                lbl_heap: "Heap-Allokation / Sys:",
                lbl_goroutines: "Goroutines:",
                lbl_gc_runs: "GC-Läufe:",
                lbl_process_uptime: "Prozess-Laufzeit:",
                lbl_heap_inuse: "Tatsächliche Heap-Nutzung:",
                lbl_heap_objects: "Aktive Heap-Objekte:",
                lbl_stack_inuse: "Goroutine-Stack-Nutzung:",
                lbl_next_gc: "Nächster GC-Schwellwert:",
                lbl_last_gc_pause: "Letzte GC-Pause:",
                lbl_gc_cpu: "GC-CPU-Anteil:",
                lbl_gomaxprocs: "GOMAXPROCS:",
                lbl_cpu_cores: "CPU-Kerne:",
                security_title: "🛡️ Sicherheits- & Verschlüsselungs-Status",
                badge_protected: "Geschützt",
                lbl_psk_status: "PSK-Mesh-Status:",
                lbl_traffic_obfs: "Datenverkehrs-Verschleierung:",
                lbl_id_fingerprint: "Identitäts-Fingerabdruck:",
                lbl_autonat_reach: "AutoNAT-Erreichbarkeit:",
                lbl_per_peer_enc: "Verschlüsselung pro Peer:",
                sec_copy: "Kopieren",
                sec_copied: "Kopiert",
                sec_peer_title: "Peer-Verschlüsselungsdetails",
                sec_peer_id: "Peer-ID",
                sec_peer_algo: "Chiffre",
                sec_peer_pfs: "Perfect Forward Secrecy",
                sec_yes: "Ja",
                sec_no: "Nein",
                sec_peer_tx_fp: "TX-Schlüssel-Fingerabdruck (SHA-256, erste 8 Hex)",
                sec_peer_rx_fp: "RX-Schlüssel-Fingerabdruck (SHA-256, erste 8 Hex)",
                sec_peer_pfs_eph: "Ephemeraler ECDH-Public-Key-Fingerabdruck",
                sec_peer_epoch_local: "Lokale Handshake-Epoche",
                sec_peer_epoch_peer: "Peer-Handshake-Epoche",
                sec_peer_copy: "Kopieren",
                sec_peer_close: "Schließen",
                sec_click_details: "Klicken für Details und zum Kopieren",
                no_peers_enc: "Keine Peers verbunden",
                protocol_dist_title: "🥧 Protokoll-Verkehrsverteilung",
                public_unencrypted: "Öffentlich (Unverschlüsselt)",
                encrypted_overlay: "Verschlüsselt (Noise/PSK)",
                disabled: "Deaktiviert",
                online: "ONLINE (2s Auto-Aktualisierung)",
                refresh: "🔄 Aktualisieren",
                settings: "⚙️ Einstellungen",
                tap_ipv4: "Virtuelle IPv4-Adresse",
                tap_ipv4_sub: "Layer-2 Virtuelles Ethernet",
                tap_ipv6: "Virtuelle IPv6-Adresse",
                tap_ipv6_sub: "Nativer Dual-Stack-Betrieb",
                tx_bytes: "Gesendete Daten (TX)",
                rx_bytes: "Empfangene Daten (RX)",
                pkts_total: "Pakete gesamt: ",
                dedup_count: "Deduplizierte Pakete",
                dedup_sub: "Mehrpfad-Duplikatfilterung",
                topology_mesh: "🕸️ Interaktives P2P-Topologie-Netz",
                topo_filter_label: "Filter:",
                topo_filter_all: "Alle",
                topo_filter_direct: "Direkt",
                topo_filter_relayed: "Über Relais",
                topo_click_hint: "Klicke einen Knoten, um Details zu sehen und seinen Pfad hervorzuheben",
                topo_clear_sel: "Schließen",
                ping_tool: "📡 P2P-Netzwerkdiagnose (Ping & Traceroute)",
                run_ping: "🚀 Ping-Test ausführen",
                run_trace: "🔍 Traceroute ausführen",
                ping_placeholder: "z.B. 10.0.0.2 oder 12D3KooW...",
                active_peers: "⚡ Aktive P2P-Knoten",
                routes_table: "🛣️ Intelligente P2P-Routing-Tabelle",
                stat_total_routes: "Berechnete Routen gesamt",
                stat_relayed_routes: "Relay-beschleunigte Pfade",
                stat_max_savings: "Max. Latenzreduzierung",
                stat_mesh_health: "Netzwerktopologie-Status",
                arp_table: "📋 Virtuelle ARP/NDP-Nachbartabelle",
                ip_analytics: "📊 24h-IP-Datenverkehrsanalyse",
                mac_table: "🔀 Virtuelle Switch MAC-Tabelle",
                no_routes: "Keine Routeneinträge berechnet",
                col_dest: "Zielknoten",
                col_hops: "Hops",
                col_optimal_path: "Visueller Pfad",
                col_total_rtt: "Optimale RTT",
                col_direct_rtt: "Direkte RTT",
                col_optimization: "Beschleunigung",
                col_route_status: "Routen-Status",
                col_nodename: "Knotenname",
                col_role: "Rolle",
                col_osarch: "BS / Arch",
                col_tapip: "PEER IP",
                col_tap_ip: "Virtuelle IP",
                col_nat: "NAT-Status",
                col_peerid: "Peer-ID",
                col_multiaddr: "Netzwerk Multiaddr",
                col_transport: "Transport",
                col_uptime: "Laufzeit",
                col_rtt: "RTT-Latenz",
                col_ip: "IP-Adresse",
                col_mac: "MAC-Adresse",
                col_rate: "Echtzeitrate",
                col_ip_attr: "Knoten / Zuordnung",
                col_target_peer: "Zugehörige Peer-ID",
                col_type: "Typ",
                col_tx_traffic: "Gesendeter Verkehr",
                col_rx_traffic: "Empfangener Verkehr",
                col_total_traffic: "Verkehr gesamt",
                col_pkts: "Pakete",
                col_last_active: "Zuletzt aktiv",
                ip_scope_local: "Lokaler TAP",
                ip_scope_peer: "Mesh-Peer",
                ip_scope_subnet: "LAN-Subnetz",
                ip_scope_exit: "Exit-Gateway",
                ip_scope_special: "L2-Spezial",
                ip_scope_wan: "WAN-Internet",
                btn_disconnecting: "Trennen...",
                topo_badge_peer: "Mesh-Peer",
                via: "über",
                no_peers: "Keine aktiven P2P-Knoten verbunden",
                no_arps: "Keine Einträge in ARP-Tabelle",
                no_ips: "Keine IP-Verkehrsdaten vorhanden",
                no_macs: "Keine Eintragsdaten in MAC-Tabelle",
                col_mac_origin: "Quelle",
                mac_origin_self: "Peer-IF",
                mac_origin_lan: "LAN-Fwd",
                mac_origin_self_tip: "Die eigene virtuelle TAP-Schnittstellen-MAC dieses Peers (lokal verwaltet, beginnt mit 02:xx:…). Ein gesunder Peer hat genau eine.",
                mac_origin_lan_tip: "Ein Gerät im LAN dieses Peers (über Bridge/Forwarding), nicht der Peer selbst. Mehrere Einträge bedeuten, dass der Peer seinen LAN-Verkehr weiterleitet.",
                mac_lan_warn: "Peer {peer} leitet {n} LAN-Gerät(e) weiter — normal, wenn der Peer sein LAN bridge/forwarded, kein Fehler.",
                retrieving_metrics: "Metriken werden abgerufen...",
                modal_title: "⚙️ p2ptap-Knotenkonfiguration",
                node_name_lbl: "Knotenname",
                strategy_lbl: "Transportstrategie",
                psk_lbl: "Pre-Shared Key (PSK)",
                psk_placeholder: "Leer lassen für öffentliches Netz, Schlüssel für Verschlüsselung",
                loglevel_lbl: "Protokollstufe",
                obfs_lbl: "Obfuskationsmodus",
                obfs_fixed_size_lbl: "Feste Paketgröße",
                obfs_fixed_size_desc: "Ziel-MTU für feste Auffüllung (Bytes)",
                bootstrap_lbl: "Bootstrap-Relay-Peers",
                section_identity: "Knotenidentität",
                section_identity_desc: "Name und Verschlüsselungseinstellungen dieses Knotens",
                node_name_desc: "Menschenlesbare Kennung für das Dashboard",
                psk_desc: "Leer für öffentliches Netz, Schlüssel für Verschlüsselung",
                section_transport: "Transport & Protokollierung",
                section_transport_desc: "Routing-Strategie und Diagnose-Ausführlichkeit",
                strategy_desc: "Wie Pakete über P2P-Verbindungen geroutet werden",
                loglevel_desc: "Steuert die Ausführlichkeit der Konsolenausgabe",
                enable_mdns_lbl: "mDNS LAN-Knotenerkennung aktivieren",
                enable_mdns_desc: "Erkennt Peers im selben LAN automatisch via mDNS (nur lokales Netzwerk)",
                cfg_disable_relay_lbl: "Circuit-Relay deaktivieren (Diagnose)",
                cfg_disable_relay_desc: "Deaktiviert libp2p Circuit-Relay, AutoRelay & DCUtR Hole-Punching (Neustart erforderlich). Hat keine Auswirkungen auf das p2ptap-Overlay-Relay.",
                section_obfs: "Verkehrsobfuskation",
                section_obfs_desc: "Paketauffüllung zur Abwehr von DPI-Fingerprinting",
                obfs_mode_desc: "Auffüllstrategie für P2P-Datenrahmen",
                section_bootstrap: "Bootstrap-Peers",
                section_bootstrap_desc: "Initiale Relay-Knoten für die Netzwerkerkennung",
                bootstrap_placeholder: "Eine Multiaddr pro Zeile",
                cfg_add_item: "➕ Hinzufügen",
                cfg_list_empty: "Keine Einträge.",
                drag_handle_tip: "Ziehen zum Neuordnen",
                drag_rule_tip: "Regel ziehen zum Neuordnen",
                move_up_tip: "Nach oben",
                move_down_tip: "Nach unten",
                acl_action_accept: "ERLAUBEN",
                acl_action_drop: "VERWERFEN",
                acl_dir_both: "↔ Beide",
                acl_dir_in: "↓ Eingehend",
                acl_dir_out: "↑ Ausgehend",
                acl_proto_any: "ALLE",
                acl_proto_tcp: "TCP",
                acl_proto_udp: "UDP",
                acl_proto_icmp: "ICMP",
                acl_no_rules_short: "Keine benutzerdefinierten ACL-Regeln (zum Erstellen auf „Regel hinzufügen\" klicken)",
                cancel_btn: "Abbrechen",
                save_btn: "Speichern & Anwenden",
                save_success: "Konfiguration erfolgreich gespeichert!",
                cfg_needs_restart: "⚠️ Relay deaktivieren geändert — zum Übernehmen p2ptap neu starten.",
                save_failed: "Fehler beim Speichern: ",
                req_error: "Speicheranfragefehler: ",
                unnamed_node: "Unbenannter Knoten",
                via_exit_node: "🚀 via Exit-Node",
                via_exit_node_hint: "Traffic über das ausgewählte Exit-Node-Gateway geroutet",
                public_direct: "Direkt (Öffentlich)",
                relayed_conn: "Relay",
                relay_only: "Nur Relay",
                not_configured: "Nicht konfiguriert",
                log_count: "{n} Logs",
                log_listening: "Warte auf Live-Logereignisse...",
                multiaddr_placeholder: "/ip4/1.2.3.4/udp/4001/quic-v1/p2p/12D3KooW...",
                exit_wan_placeholder: "auto (physische Ausgangsschnittstelle automatisch erkennen)",
                exit_status_title: "Live-Status",
                exit_status_inactive: "Kein Exit-Node-Tunnel aktiv",
                exit_status_role_client: "Client",
                exit_status_role_server: "Server (bietet Ausgang)",
                exit_status_role_both: "Client + Server",
                exit_status_routing_via: "Datenverkehr läuft über",
                exit_status_offering: "Bietet Ausgang für das Mesh",
                exit_status_peer: "Peer",
                exit_status_tap_ip: "TAP IP",
                exit_status_tap_ipv6: "TAP IPv6",
                subnets_placeholder: "z.B. 192.168.1.0/24",
                allowed_peers_placeholder: "z.B. * oder 12D3KooW...",
                delete_rule: "🗑️ Löschen",
                acl_peer_placeholder: "Peer-ID oder *",
                acl_cidr_placeholder: "Ziel-CIDR oder *",
                acl_port_placeholder: "Port / Bereich",
                echo_test: "🧪 Echo-Test",
                echo_test_hint: "💡 Klicken Sie auf eine Echo Test-Schaltfläche, um die Latenz über einen bestimmten Multiaddr-Pfad zu messen.",
                test_all: "🧪 Alle testen",
                speedtest_btn: "⚡ Geschwindigkeitstest",
                test_echo: "⚡ Echo testen",
                probing_text: "⏳ Prüfe...",
                probe_result: "🧪 {reachable}/{total} Adressen erreichbar",
                probe_error: "🧪 Prüfungsfehler",
                probing_echo: "🚀 Prüfe Echo-Stream über {addr}...",
                probing_pathways_title: "🧪 Prüfe Multiaddr-Pfade...",
                probing_pathways_desc: "Teste Stream-Erreichbarkeit, RTT und Transporttypen...",
                accept_subnets_lbl: "Angekündigte Subnetze von Remote-Peers akzeptieren",
                acl_default_action_lbl: "Standardrichtlinie für nicht übereinstimmenden Datenverkehr",
                acl_flow_title: "Sequenzieller Regelfluss:",
                acl_flow_hint_permit: "Erlaubnis-Ausnahmeliste — diese Regeln ALLOW'en passenden Datenverkehr, entgegen der Standard-DROP-Richtlinie.",
                acl_flow_hint_block: "Sperr-Ausnahmeliste — diese Regeln DENY'en passenden Datenverkehr, entgegen der Standard-ACCEPT-Richtlinie.",
                acl_open_desc: "Mesh-Firewall ist offen (aller P2P-Datenverkehr erlaubt)",
                acl_badge_open: "Offenes Mesh",
                acl_badge_active: "● Aktiv",
                acl_open_hint: "ACL unter Einstellungen → ACL-Editor aktivieren, um Regeln durchzusetzen.",
                acl_label_rules: "Regeln",
                acl_label_default: "Standard",
                acl_label_accepted: "Akzeptiert",
                acl_label_dropped: "Verworfen",
                acl_label_uptime: "Laufzeit",
                acl_label_top_rules: "Meistgenutzte Regeln",
                acl_label_recent_drops: "Letzte Verwürfe",
                acl_label_default_action: "Standard",
                acl_label_hits: "Treffer",
                acl_label_more: "weitere",
                acl_default_accept: "ACCEPT (erlauben)",
                acl_default_drop: "DROP (verweigern)",
                strategy_redundant: "Doppelt senden (redundant)",
                strategy_fallback: "Failover (Rückfall)",
                log_level_debug: "Ausführliches Debug",
                log_level_info: "Standardinformationen",
                log_level_warn: "Nur Warnungen",
                log_level_error: "Nur Fehler",
                obfs_fixed: "Feste Größe (Padding)",
                obfs_block: "Block-Mehrfach",
                obfs_random: "Zufällige Länge",
                obfs_dynamic: "Variabler Bereich",
                obfs_auto: "Auto-Erkennung & Wechsel",
                acl_editor_title: "🛡️ ACL-Regeleditor",
                acl_no_rules: "Noch keine benutzerdefinierten ACL-Regeln — eine hinzufügen oder Vorlage wählen.",
                acl_test_title: "🧪 ACL-Regeltester",
                acl_test_peer: "Quell-Peer-ID",
                acl_test_dir: "Richtung",
                acl_test_proto: "Protokoll",
                acl_test_dstip: "Ziel-IP",
                acl_test_dstport: "Zielport",
                acl_test_allow: "ERLAUBT",
                acl_test_deny: "VERWEIGERT",
                acl_test_matched: "Zutreffende Regel",
                acl_test_default: "Keine Regel traf — Standardrichtlinie angewendet",
                acl_template_lbl: "Vorlage einfügen…",
                acl_comment_placeholder: "Kommentar / Beschreibung",
                close_btn: "Schließen",
                acl_status_title: "🛡️ Firewall",
                active_exit_badge: "⚡ Aktives Gateway",
                active_pathway: "Aktuell aktiver verbundener Pfad",
                active_pathway_unknown: "Keine aktive Verbindung",
                best_reachable_pathway: "Bester erreichbarer Kandidat (aus letzter Multiaddr-Probe)",
                probe_unverified: "unverifiziert",
                add_rule_btn: "➕ Regel hinzufügen",
                adv_subnets_lbl: "Angekündigte Subnetze (CIDR, eine pro Zeile)",
                allowed_subnet_peers_lbl: "Erlaubte Subnetz-Peer-IDs (* für allen vertrauen, eine pro Zeile)",
                badge_subnet_disabled: "⏸️ Deaktiviert",
                bandwidth_chart_title: "📈 Live-Bandbreiten-Wellenform (Tx / Rx)",
                btn_cancel: "Abbrechen",
                btn_close: "Schließen",
                btn_connect_exit: "🚀 Exit-Gateway verbinden",
                exit_picker_hint: "Peer oben auswählen, um Datenverkehr zu routen",
                btn_disable_subnet: "🛑 Deaktivieren",
                btn_disconnect_exit: "⏹️ Exit trennen",
                btn_enable_subnet: "▶️ Aktivieren",
                btn_test_save_peer: "➕ Peer testen & permanent speichern",
                chosen_optimal: "🟢 Optimaler Pfad gewählt",
                clear_exit_node_btn: "🛑 Disconnect Exit",
                col_candidate_path: "Kandidatenpfad",
                col_exit_egress: "Exit-Node-Ausgangsverkehr",
                col_inspector: "Entscheidungs-Inspektor",
                col_last_sync: "Zuletzt gehört",
                col_rationale: "Entscheidungs- / Ablehnungsgrund",
                col_rtt_end: "Ende-zu-Ende-RTT",
                col_status: "Status",
                col_subnets: "Angekündigte Subnetze",
                col_sync_channel: "Ermittlungskanal",
                col_tapmac: "TAP-MAC",
                common_failed: "FEHLER",
                common_idle: "im Leerlauf",
                common_ok: "OK",
                common_peer: "Peer",
                common_read: "Lesen",
                common_rtt: "RTT",
                common_unknown: "unbekannter Fehler",
                common_unknown_write_error: "unbekannter Schreibfehler",
                common_write: "Schreiben",
                copied_toast: "📋 Config-JSON in Zwischenablage kopiert!",
                desc_arp: "Layer-2 Address Resolution",
                desc_broadcast: "L2-Broadcast (inkl. ARP)",
                desc_gateway: "Tunnel über Exit-Node",
                desc_icmp: "Netzwerk-Sonden & Keepalive",
                desc_multicast: "L2-Multicast (inkl. mDNS)",
                desc_seq_sync: "Synchronisierte Peers · Wiedergabe / Fenster-Verwürfe",
                desc_tcp: "Zuverlässige Byte-Streams",
                desc_udp: "Datagramm-Transport",
                direct_optimal_desc: "Direkte physische Latenz ist schneller als jede Kandidaten-Multihop-Relay-Route",
                direct_optimal_title: "Direktes P2P gewählt (niedrigste Latenz)",
                disc_addrs: "Ermittelte Adresspfade",
                enable_acl_lbl: "ACL-Firewall-Engine aktivieren",
                err_enter_multiaddr: "Bitte gültige Multiaddr-Zeichenfolge eingeben",
                eval_table_title: "📊 Dijkstra-Routing-Engine - ausgewertete Kandidatenpfade",
                exit_client_card_title: "🚀 Exit-Node-Gateway-Steuerung",
                exit_client_no_peers: "Derzeit keine Online-Peers mit Exit-Node-Ausgang",
                exit_client_status_active: "⚡ Gesamten Internetverkehr über Exit-Node leiten",
                exit_client_status_inactive: "Kein aktives Exit-Gateway (lokales Standardgateway wird verwendet)",
                exit_connected: "🚀 Exit gateway connected to ",
                exit_disconnected: "🛑 Exit-Gateway getrennt",
                exit_enable_desc: "Internetverkehr über diesen Peer leiten",
                exit_enable_lbl: "Exit-Node-Gateway-Modus aktivieren",
                exit_nat_desc: "Quelladressübersetzung für ausgehenden Datenverkehr",
                exit_nat_lbl: "SNAT / Masquerade aktivieren (Quelladressübersetzung)",
                exit_node_badge: "🌐 Exit-Node",
                exit_node_desc: "Internet-Ausgangsrouting über diesen Knoten",
                exit_node_title: "🌐 Exit-Node-Gateway-Einstellungen",
                exit_wan_lbl: "WAN-Ausgangsschnittstelle (z. B. eth0 oder auto)",
                inspect_btn: "🔍 Untersuchen",
                inspector_title: "🧭 Smart-Routing-Entscheidungs-Inspektor",
                lbl_arp_broadcast: "ARP Broadcast Frames",
                lbl_broadcast_pkts: "Broadcast-Pakete",
                lbl_gateway_pkts: "Exit-Node-Gateway-Pakete",
                lbl_icmp_ping: "ICMP-Echo (Ping)",
                lbl_multiaddr_str: "Multiaddr-Zeichenfolge",
                lbl_multicast_pkts: "Multicast-Pakete",
                lbl_seq_sync: "Seq-Sync & Deduplizierung",
                lbl_tcp_packets: "TCP-Stream-Pakete",
                lbl_udp_packets: "UDP-Transport-Pakete",
                logs_cleared: "Protokolle geleert.",
                matrix_dst: "Zielknoten",
                matrix_hops: "Hops",
                matrix_rtt: "RTT-Latenz",
                matrix_src: "Quellknoten",
                matrix_type: "Verbindungstyp",
                mesh_matrix_title: "🕸️ Mesh-Qualitäts- und Latenzmatrix",
                modal_add_static_desc: "Vollständige P2P-Multiaddr mit Ziel /p2p/<PEER_ID> eingeben. Adresse wird dauerhaft im Peerstore mit PermanentAddrTTL registriert und automatisch verbunden.",
                modal_add_static_title: "➕ Permanente statische Peer-Multiaddr hinzufügen",
                modal_diag_title: "⚡ Peer-Pfad-Diagnose & Benchmark",
                nat_fallback_desc: "umgeht Symmetric-NAT-Isolation, wenn direkte P2P-Verbindung nicht erreichbar",
                no_matrix: "Keine Peer-Routen in Matrix",
                no_peer_metas: "Keine Peer-Metadaten über peek-map / P2P empfangen",
                no_subnets: "Keine aktiven angekündigten Subnetze",
                dup_ip_conflicts_title: "⚠️ Doppelte IP / Subnetz-Konflikte",
                no_dup_ip_conflicts: "Keine doppelten IP- oder Subnetz-Konflikte erkannt",
                dup_winner: "Gewinner",
                obfs_allow_switch_lbl: "Automatischen Moduswechsel erlauben",
                obfs_strict_key_lbl: "Strenge Schlüsselaushandlung (PFS)",
                obfs_strict_key_desc: "Fallback auf den langlebigen Knotenschlüssel verbieten. Jedes Peer-Paar muss einen eigenen Cipher aus einem einmaligen ECDH-Ephemeralschlüssel ableiten, sonst bleibt dieses Peer-Paar im Klartext. Härtet die Schlüsselisolation pro Peer.",
                obfs_auto_title: "🤖 Automatische Erkennung",
                obfs_block_size_desc: "Ausrichtungsgranularität für Blockmodus (Bytes)",
                obfs_block_size_lbl: "Block-Ausrichtungsgröße",
                obfs_dynamic_desc: "Min–Max-Bereich für variabel große Frames",
                obfs_dynamic_lbl: "Dynamischer Größenbereich (Bytes)",
                obfs_eval_interval_lbl: "Auswertungsintervall",
                obfs_jitter_desc: "Random jitter to break fixed-size patterns (0=off)",
                obfs_jitter_lbl: "Jitter-Bereich (±Bytes)",
                obfs_max_safe_desc: "PMTU safety threshold for obfuscated frames (bytes)",
                obfs_max_safe_lbl: "Max Safe Frame Size",
                obfs_threshold_lbl: "Schwellenwert",
                packet_rate_title: "📊 Paketraten-Verteilung (Tx / Rx)",
                pcap_layer_frame: "Frame",
                pcap_layer_tree: "Protokoll-Analyse",
                peer_meta_title: "📡 Peer-Metadaten & Peek-Map-Erkennungsmonitor",
                peer_traffic_title: "Peer Live Broadcasted Rate & Traffic",
                protocol_inspector_desc: "（Layer-2/3/4-Paketaufschlüsselung & Live-PPS-Statistik）",
                protocol_inspector_title: "📊 Live-Datenverkehr & Ethernet-Protokoll-Inspektor",
                proto_channels_title: "📡 Protokoll-Streams & Kanalüberwachung",
                th_stream_proto: "Protokoll / Kanal",
                th_stream_peer: "Gegenstelle",
                th_stream_direction: "Richtung",
                th_stream_transport: "Transport & Multiaddr",
                th_stream_status: "Status",
                search_streams_ph: "Streams, Protokolle, Peers durchsuchen…",
                no_matching_streams: "Keine aktiven Protokoll-Streams gefunden",
                no_channels: "Keine aktiven Protokollkanäle",
                lbl_active_streams: "Streams",
                lbl_streams: "Streams",
                dir_out: "Ausgehend ↑",
                dir_in: "Eingehend ↓",
                stream_active: "Aktiv",
                channel_status_active: "Aktiv",
                channel_status_running: "Wird ausgeführt",
                channel_status_idle: "Inaktiv",
                channel_status_standby: "Bereitstehend",
                channel_status_ready: "Bereit",
                channel_status_open: "Offener Modus",
                category_sync: "Synchronisation",
                category_routing: "Routing",
                category_pubsub: "PubSub",
                category_data: "Datenübertragung",
                category_security: "Sicherheit",
                category_transport: "Transport",
                category_diagnostics: "Diagnose",
                category_discovery: "Erkennung",
                channel_seqsync_name: "Sequenz-Sync (SeqSync)",
                channel_seqsync_desc: "Fenster-Deduplizierung & Replay-Schutz",
                channel_lsa_name: "LSA-Mesh-Routing",
                channel_lsa_desc: "Dijkstra-Kürzester-Pfad-Routing",
                channel_peekmap_name: "Peek-Map Topologie-Broadcast",
                channel_peekmap_desc: "Bootstrap-Topologie-Synchronisation",
                channel_data_name: "Virtueller TAP-Datenpfad",
                channel_data_proto: "Layer-2-Ethernet-Overlay",
                channel_auth_name: "PSK-Mesh-Authentifizierung",
                channel_auth_desc: "PSK-Mesh-Netzwerkisolation",
                channel_dcutr_name: "DCUtR Lochstanzen & Relay",
                channel_dcutr_desc: "Direktverbindungs-Upgrade",
                cipher_lbl: "Chiffre",

                rejected: "❌ Abgelehnt",
                relay_accel_active: "Relay-Beschleunigung aktiv",
                relay_accel_desc: "Dijkstra-Algorithmus berechneter Multihop-Pfad über",
                relay_chosen_title: "Smart-Relay gewählt",
                reset_view: "🎯 Ansicht zurücksetzen",
                saved_latency: "gespart",
                section_acl_title: "🛡️ ZeroTier-artiger P2P-Mesh-ACL-Regeleditor",
                section_acl_desc: "Pro-Peer-Filterregeln für den Datenverkehr",
                section_subnet_title: "🌐 Subnetz-Router & Autorisierung",
                section_subnet_desc: "Subnetze ankündigen und Peers für deren Nutzung autorisieren",
                set_as_exit_btn: "🚀 Set as Gateway",
                subnet_no_toggle: "Nicht routbar",
                subnet_routes_title: "🌐 Subnetz-Routen",
                badge_subnet_pending: "⛔ Autorisierung ausstehend",
                target_node: "🎯 Zielknoten",
                toast_add_failed: "Hinzufügen des statischen Peers fehlgeschlagen",
                toast_req_err: "Anforderungsfehler",
                toast_static_added: "Statischer Peer hinzugefügt und dauerhaft im Peerstore registriert!",
                toast_subnet_disabled: "⏸️ Subnetz-Route {cidr} in Echtzeit deaktiviert",
                toast_subnet_enabled: "▶️ Subnetz-Route {cidr} in Echtzeit aktiviert",
                toast_testing_adding: "Teste und füge statischen Peer hinzu",
                topo_reset_layout: "📌 Reset Layout",
                topo_reset_zoom: "🔍 Reset View",
                topo_self_node: "Eigener Knoten",
                topo_standalone: "🌐 Eigenständiger Mesh-Knoten (wartet auf P2P-Peer-Verbindungen...)",
                topology_sub: "（Knoten ziehen zum Verschieben | Scrollen zum Zoomen | Doppelklick für Ping）",
                topology_title: "🗺️ Topologie-Sternbild",
                troubleshoot_fail: "FEHLER",
                troubleshoot_idle: "Wählen Sie einen Peer und klicken Sie auf „Vollständige Diagnose ausführen“, um Konnektivitätsprobleme zu beheben.",
                troubleshoot_manual_input: "Oder Peer-ID manuell eingeben...",
                troubleshoot_no_peer: "Bitte Peer zum Diagnostizieren auswählen oder eingeben",
                troubleshoot_pass: "ERFOLG",
                troubleshoot_run: "🔍 Vollständige Diagnose ausführen",
                troubleshoot_running: "LAUFEND",
                troubleshoot_select_peer: "Peer zur Diagnose auswählen",
                troubleshoot_skip: "ÜBERSPRINGEN",
                troubleshoot_step1: "Lokale TAP-Schnittstellenprüfung",
                troubleshoot_step2: "Peer-Erkennung & Verbindungsstatus",
                troubleshoot_step3: "libp2p-Stream-Konnektivitätsprüfung",
                troubleshoot_step4: "Transport-Level-Multiaddr-Prüfung",
                linkcheck_title: "🔗 Multiaddr-Linkprüfung",
                linkcheck_desc: "Tiefe Transportschicht-Diagnose: Multiaddr gültig → DNS → TCP/QUIC → libp2p-Transport → Noise/TLS-Handshake → Peer-ID-Abgleich → Verbindung.",
                linkcheck_input_ph: "Vollständige P2P-Multiaddr eingeben, z. B. /ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...",
                linkcheck_btn: "🔗 Linkprüfung starten",
                linkcheck_inline: "🔗 Prüfen",
                linkcheck_inline_title: "7-stufige Link-Diagnose für diese Multiaddr ausführen",
                linkcheck_running: "Linkprüfung läuft…",
                linkcheck_no_input: "Bitte eine Multiaddr zur Prüfung eingeben.",
                linkcheck_overall: "Gesamtergebnis",
                linkcheck_peer: "Ziel-Peer",
                linkcheck_input: "Getestete Multiaddr",
                linkcheck_transport: "Transport",
                linkcheck_resolved: "Aufgelöste IPs",
                linkcheck_step1: "Multiaddr gültig",
                linkcheck_step2: "DNS Auflösung",
                linkcheck_step3: "TCP / QUIC etabliert",
                linkcheck_step4: "libp2p-Transport",
                linkcheck_step5: "Noise / TLS-Handshake",
                linkcheck_step6: "Peer-ID-Abgleich",
                linkcheck_step7: "libp2p-Verbindung",
                troubleshoot_step5: "Overlay-Routing-Pfadanalyse",
                troubleshoot_step6: "ARP/NDP-Auflösungsprüfung",
                troubleshoot_step7: "ACL- & Sicherheitsrichtlinienprüfung",
                troubleshoot_step8: "TAP-Gerät Lese-/Schreib-Selbsttest",
                troubleshoot_step8_device: "Gerät",
                troubleshoot_step8_loopback_fail: "TAP-Loopback erwartet, aber kein Frame zurückgelesen",
                troubleshoot_step8_loopback_ok: "Loopback verifiziert",
                troubleshoot_step8_request_fail: "TAP-Selbsttest-Anforderung fehlgeschlagen",
                troubleshoot_step8_running: "Führe TAP-Gerät Lese-/Schreib-Selbsttest aus…",
                troubleshoot_step8_stale_binary: "Der Endpunkt /api/tap/selftest antwortete nicht mit JSON. Die ausgeführte Binärdatei ist wahrscheinlich veraltet — p2ptap neu erstellen und neu starten.",
                troubleshoot_step8_unavailable: "TAP-Selbsttest auf diesem Knoten nicht verfügbar.",
                troubleshoot_step8_wintun_noloop: "kein Loopback — Wintun ist ein L3-Tunnel, wie erwartet",
                troubleshoot_step8_write_fail: "TAP-Schreibpfad FEHLGESCHLAGEN.",
                troubleshoot_step9: "Ende-zu-Ende-TAP-Datenpfad-Weiterleitungstest",
                troubleshoot_step9_fail: "TAP-Weiterleitungstest fehlgeschlagen.",
                troubleshoot_step9_fail_detail: "TAP-Weiterleitungstest fehlgeschlagen — der TAP-Datenpfad ist defekt, obwohl Echo (Schritt 7) bestanden wurde.",
                troubleshoot_step9_hint: "Wahrscheinlich ein defekter Overlay-Unicast-/Relay-Pfad oder ein TAP-Frame-Verarbeitungsproblem auf Peer-Seite. Prüfen Sie den Relay-Pfad und das TAP-Gerät des Peers.",
                troubleshoot_step9_pass: "TAP-Frame-Hin- und Rückweg OK (ICMP-Echo-Anforderung → Peer → ICMP-Echo-Antwort).",
                troubleshoot_step9_request_fail: "TAP-Weiterleitungstest-Anforderung fehlgeschlagen",
                troubleshoot_step9_running: "Injecting eines TAP-Frames (ICMP-Echo-Anforderung) in das Overlay Richtung Peer-TAP-IP…",
                troubleshoot_step9_sent: "Gesendet",
                troubleshoot_title: "🔧 P2P-Konnektivitäts-Fehlersuche",
                troubleshoot_warn: "WARN",
                unreachable: "Nicht erreichbar",
                view_addr: "Multiaddr anzeigen",
                vs_direct: "im Vergleich zum direkten Pfad",
                col_encryption: "Verschlüsselung",
                topo_legend_direct_fast: "● Direkt (<30ms)",
                topo_legend_direct_slow: "● Direkt (30-100ms)",
                topo_legend_relay: "● Transit-Relay (bernstein) — relayte Peers hängen darunter",
                topo_legend_flow: "💧 Flussdichte = echte TX/RX-Rate (im Leerlauf fließen keine Links)",
                topo_badge_transit: "🌉 Transit-Switch",
                topo_badge_exit_server: "🚪 Exit-Server",
                topo_via: "über",
                topo_link_idle: "inaktiv",
                topo_summary_nodes: "Knoten",
                topo_summary_direct: "Direkt",
                topo_summary_relayed: "Über Relais",
                topo_summary_relays: "Transit-Relays",
                topo_summary_thru: "Mesh-Durchsatz",
                topo_summary_gw: "Gateway-Pakete",
                topo_summary_boots: "Bootstraps",
                topo_summary_static: "Statische Peers",
                topo_summary_clusters: "Cluster",
                topo_filter_remote: "Clusterübergreifend",
                topo_legend_boot: "● Bootstrap-Knoten (lila)",
                topo_legend_overlay: "◆ Overlay-Relay (lange Linie)",
                topo_badge_boot: "Bootstrap",
                topo_badge_static: "Statisch",
                topo_tt_role_boot: "Bootstrap-Knoten",
                topo_tt_role_static: "Statischer Peer",
                topo_tt_cluster: "Cluster:",
                topo_tt_boot_hops: "Boot-Hops:",
                topo_tt_transport_path: "Transportpfad:",
                topo_tt_relay_hop: "Relay-Hop:",
                topo_tt_enc: "Verschlüsselung:",
                topo_tt_conn: "Verbindungsstatus:",
                topo_tt_jitter: "Jitter:",
                topo_tt_loss: "Verlust:",
                topo_tt_version: "Version:",
                topo_tt_since: "Verbunden seit:",
                topo_tt_geo: "Standort:",
                topo_tt_total: "Gesamt (Tx/Rx):",
                topo_tt_route_via: "Pfad:",
                topo_tt_blackhole: "Rx-Blackhole (Dedup-Versatz)",
                topo_tt_circuit_relay: "Circuit Relay v2",
                topo_tt_dedup_window: "Dedup-Fenster:",
                topo_tt_direct_link: "Direkte P2P-Verbindung",
                topo_tt_dup_drops: "Duplikat-Drops:",
                topo_tt_healthy: "Gesund",
                topo_tt_ipv4: "Virtuelles IPv4:",
                topo_tt_ipv6: "Virtuelles IPv6:",
                topo_tt_link_integrity: "Link-Integrität:",
                topo_tt_live_rate: "Live-Rate:",
                topo_tt_local_host: "Lokaler Host",
                topo_tt_optimal_route: "Optimale Route:",
                topo_tt_os_arch: "OS / Arch:",
                topo_tt_peer_id: "Peer-ID:",
                topo_tt_route: "Route:",
                topo_tt_route_gain: "Routen-Gewinn:",
                topo_tt_rtt: "RTT-Latenz:",
                topo_tt_seq: "Seq (Tx/Rx):",
                topo_tt_tap_ip: "PEER-IP:",
                topo_tt_transit_relay: "Transit-Relay",
                topo_tt_transport: "Transport:",
                topo_tt_uptime: "Laufzeit:",
            },
            es: {
                default_node_name: "Nodo VPN P2P TAP",
                login_title: "🔐 Inicio de sesión del panel P2P TAP",
                login_subtitle: "Este panel está protegido. Introduce tu token de acceso para continuar.",
                login_token_label: "Token de acceso",
                login_token_placeholder: "Pega el token del registro de inicio o config (webui.auth_token)",
                login_btn: "Iniciar sesión",
                login_error: "Token inválido o solicitud fallida. Inténtalo de nuevo.",
                login_hint: "El token se guarda localmente en tu navegador y se envía como cabecera Bearer.",
                speed_test: "⚡ Test de Velocidad P2P",
                btn_add_static_peer: "➕ Agregar Peer Estático",
                pcap_title: "🔬 Captura de Paquetes",
                pcap_stopped: "Detenido",
                pcap_running: "● Capturando",
                pcap_start: "▶️ Iniciar",
                pcap_pause: "⏸️ Pausar",
                pcap_clear: "🗑️ Limpiar",
                pcap_autoscroll: "Auto-desplazamiento",
                pcap_stream_live: "Transmisión en vivo (WebSocket)",
                pcap_stream_connecting: "Conectando…",
                pcap_stream_polling: "Sondeo como alternativa",
                pcap_stream_off: "Transmisión desconectada",
                pcap_stream_dropped: "tramas descartadas por cliente lento",
                log_stream_live: "Transmisión en vivo (WebSocket)",
                log_stream_connecting: "Conectando…",
                log_stream_polling: "Sondeo como alternativa",
                log_stream_off: "Transmisión desconectada",
                log_stream_dropped: "registros descartados por cliente lento",
                pcap_desc: "Captura tramas Ethernet crudas enviadas/recibidas en la NIC virtual TAP local (incl. MAC origen/destino, protocolo, IP, hex). <span class=\"tx-tag\">tx</span> = enviado por este host, <span class=\"rx-tag\">rx</span> = recibido. <span class=\"tx-tag\">Haz clic en cualquier fila</span> para ver detalles completos y volcado hex.",
                pcap_empty: "Sin datos aún. Haz clic en \"Iniciar\" para capturar el tráfico TAP local.",
                pcap_click_hint: "Haz clic para ver detalles completos",
                pcap_dup_repeat: "Trama repetida — idéntica a la fila anterior (reenvío mDNS / multicast)",
                pcap_dup_repeat_row: "Trama repetida — mismo payload que la fila de arriba. Comportamiento normal de mDNS / multicast, no duplicado de render.",
                pcap_modal_title: "🔬 Detalles del Paquete",
                pcap_modal_raw: "Hex completo (raw frame)",
                pcap_copy_hex: "📋 Copiar Hex",
                pcap_dir_tx: "Enviado por host (tx)",
                pcap_dir_rx: "Recibido (rx)",
                pcap_f_seq: "Seq",
                pcap_f_time: "Hora",
                pcap_f_dir: "Dirección",
                pcap_f_srcmac: "MAC Origen",
                pcap_f_dstmac: "MAC Destino",
                pcap_f_etype: "EtherType",
                pcap_f_proto: "Protocolo",
                pcap_f_vlan: "VLAN ID",
                pcap_f_l4proto: "Protocolo L4",
                pcap_f_srcip: "IP Origen",
                pcap_f_dstip: "IP Destino",
                pcap_f_srcport: "Puerto Origen",
                pcap_f_dstport: "Puerto Destino",
                pcap_f_tcpflags: "Banderas TCP",
                pcap_f_tcpseq: "Secuencia TCP",
                pcap_f_tcpwin: "Ventana TCP",
                pcap_f_dns: "Consulta DNS",
                pcap_f_sni: "TLS SNI",
                pcap_f_ttl: "TTL",
                pcap_f_arpop: "Op ARP",
                pcap_f_arpsmac: "MAC Emisor ARP",
                pcap_f_arpdmac: "MAC Objetivo ARP",
                pcap_f_frompeer: "Desde Peer",
                pcap_f_topeer: "Hacia Peer",
                pcap_f_len: "Longitud de Trama",
                pcap_f_info: "Resumen de Protocolo",
                pcap_col_seq: "#",
                pcap_col_time: "Hora",
                pcap_col_dir: "Dir",
                pcap_col_srcmac: "MAC Origen",
                pcap_col_dstmac: "MAC Destino",
                pcap_col_etype: "Tipo",
                pcap_col_proto: "Proto",
                pcap_col_srcip: "IP Origen",
                pcap_col_dstip: "IP Destino",
                pcap_col_ports: "Puertos",
                pcap_col_flags: "Flags",
                pcap_col_dns: "DNS",
                pcap_col_sni: "SNI",
                pcap_col_frompeer: "Desde Peer",
                pcap_col_topeer: "Hacia Peer",
                pcap_col_len: "Long.",
                pcap_col_info: "Resumen",
                pcap_col_hex: "Hex (primeros 64B)",
                share_config: "📲 Compartir y Exportar",
                terminal_title: "📟 Consola de Registros en Vivo",
                auto_scroll: "📜 Desplazamiento Auto: ON",
                auto_scroll_off: "📜 Desplazamiento Auto: OFF",
                clear_logs: "🗑️ Limpiar",
                pause_logs: "⏸️ Pausar",
                resume_logs: "▶️ Reanudar",
                log_paused_badge: "⏸ Pausado",
                copy_logs: "📋 Copiar",
                logs_copied: "📋 ¡Registros copiados al portapapeles!",
                logs_empty_copy: "Nada que copiar todavía.",
                copy_failed: "Copia fallida.",
                speedtest_title: "⚡ Test de Ancho de Banda y Latencia P2P",
                select_target_peer: "Seleccionar Nodo Objetivo",
                mbps_label: "Mbps (Tasa de Transferencia P2P)",
                rtt_avg: "RTT Promedio",
                jitter_lbl: "Jitter",
                quality_lbl: "Calidad",
                start_test_btn: "🚀 Iniciar Prueba",
                share_title: "📲 Compartir y Exportar Configuración",
                share_desc: "Escanee el código QR o exporte la configuración JSON para desplegar nodos.",
                copy_json: "📋 Copiar JSON",
                download_json: "💾 Descargar Archivo",
                col_geo: "Ubicación Geo",
                col_conn_time: "Tiempo Conectado",
                col_last_active: "Última Actividad",
                col_jitter_loss: "Jitter / Pérdida",
                col_status: "Estado de conexión",
                col_return_path: "Ruta de retorno",
                conn_ok: "Conectado",
                conn_relay_ok: "Relé OK",
                conn_connecting: "Conectando",
                conn_proto_mismatch: "Protocolo incompatible",
                conn_obf_failed: "Fallo de descifrado",
                conn_unreachable: "Inalcanzable",
                return_ok: "Retorno OK",
                return_dead: "Retorno cortado",
                return_idle: "Retorno desconocido",
                col_actions: "Acciones",
                topo_tx: "Ruta Ida (Tx ➔)",
                topo_rx: "Ruta Vuelta (Rx ⬅️)",
                topo_relay: "Salto Relevado",
                peer_id_lbl: "ID de Par",
                strategy_best_path: "MEJOR_RUTA",
                strategy_low_latency: "BAJA_LATENCIA",
                strategy_high_bandwidth: "ALTO_ANCHO_BANDA",
                search_placeholder: "Buscar…",
                prev_page: "‹ Anterior",
                next_page: "Siguiente ›",
                per_page: "Por página",
                no_match: "Sin coincidencias",
                sys_health_title: "💻 Estado del Sistema y Runtime",
                badge_active: "Activo",
                lbl_heap: "Asignación Heap / Sys:",
                lbl_goroutines: "Goroutines:",
                lbl_gc_runs: "Ejecuciones GC:",
                lbl_process_uptime: "Tiempo de Actividad:",
                lbl_heap_inuse: "Heap en Uso:",
                lbl_heap_objects: "Objetos Heap Activos:",
                lbl_stack_inuse: "Uso Pila Goroutines:",
                lbl_next_gc: "Próximo GC @:",
                lbl_last_gc_pause: "Última Pausa GC:",
                lbl_gc_cpu: "Fracción CPU GC:",
                lbl_gomaxprocs: "GOMAXPROCS:",
                lbl_cpu_cores: "Núcleos CPU:",
                security_title: "🛡️ Estado de Seguridad y Cifrado",
                badge_protected: "Protegido",
                lbl_psk_status: "Estado de Malla PSK:",
                lbl_traffic_obfs: "Ofuscación de Tráfico:",
                lbl_id_fingerprint: "Huella de Identidad:",
                lbl_autonat_reach: "Alcance AutoNAT:",
                lbl_per_peer_enc: "Cifrado por Peer:",
                sec_copy: "Copiar",
                sec_copied: "Copiado",
                sec_peer_title: "Detalles de Cifrado del Peer",
                sec_peer_id: "ID del Peer",
                sec_peer_algo: "Cifrado",
                sec_peer_pfs: "Secreto Adelantado Perfecto",
                sec_yes: "Sí",
                sec_no: "No",
                sec_peer_tx_fp: "Huella de Clave TX (SHA-256, primeros 8 hex)",
                sec_peer_rx_fp: "Huella de Clave RX (SHA-256, primeros 8 hex)",
                sec_peer_pfs_eph: "Huella de Clave Pública ECDH Efímera",
                sec_peer_epoch_local: "Época de Handshake Local",
                sec_peer_epoch_peer: "Época de Handshake del Peer",
                sec_peer_copy: "Copiar",
                sec_peer_close: "Cerrar",
                sec_click_details: "Clic para ver detalles y copiar huellas",
                no_peers_enc: "Sin peers conectados",
                protocol_dist_title: "🥧 Distribución de Tráfico de Protocolo",
                public_unencrypted: "Pública (Sin Cifrar)",
                encrypted_overlay: "Malla Cifrada (Noise/PSK)",
                disabled: "Desactivado",
                online: "EN LÍNEA (Actualización 2s)",
                refresh: "🔄 Actualizar",
                settings: "⚙️ Configuración",
                tap_ipv4: "Dirección IPv4 Virtual",
                tap_ipv4_sub: "Ethernet Virtual de Capa-2",
                tap_ipv6: "Dirección IPv6 Virtual",
                tap_ipv6_sub: "Soporte Nativo de Doble Pila",
                tx_bytes: "Datos Enviados (TX)",
                rx_bytes: "Datos Recibidos (RX)",
                pkts_total: "Paquetes totales: ",
                dedup_count: "Paquetes Deduplicados",
                dedup_sub: "Filtrado de Duplicados Multienlace",
                topology_mesh: "🕸️ Malla Topológica P2P Interactiva",
                topo_filter_label: "Filtrar:",
                topo_filter_all: "Todos",
                topo_filter_direct: "Directo",
                topo_filter_relayed: "Relevado",
                topo_click_hint: "Haz clic en un nodo para ver detalles y resaltar su ruta",
                topo_clear_sel: "Cerrar",
                ping_tool: "📡 Diagnóstico de Red P2P (Ping y Traceroute)",
                run_ping: "🚀 Ejecutar Prueba Ping",
                run_trace: "🔍 Ejecutar Traceroute",
                ping_placeholder: "ej. 10.0.0.2 o 12D3KooW...",
                active_peers: "⚡ Nodos P2P Activos",
                routes_table: "🛣️ Tabla de Enrutamiento Inteligente P2P Overlay",
                stat_total_routes: "Rutas Calculadas Totales",
                stat_relayed_routes: "Rutas Aceleradas por Relé",
                stat_max_savings: "Reducción Máx. Latencia",
                stat_mesh_health: "Estado Topológico de Red",
                arp_table: "📋 Tabla de Vecinos ARP / NDP Virtual",
                ip_analytics: "📊 Análisis de Tráfico por IP 24h",
                mac_table: "🔀 Tabla MAC del Conmutador Virtual",
                no_routes: "Aún no se han calculado rutas",
                col_dest: "Nodo Destino",
                col_hops: "Saltos",
                col_optimal_path: "Ruta Visual",
                col_total_rtt: "RTT Óptimo",
                col_direct_rtt: "RTT Directo",
                col_optimization: "Aceleración",
                col_route_status: "Estado de Ruta",
                col_nodename: "Nombre del Nodo",
                col_role: "Rol",
                col_osarch: "SO / Arq",
                col_tapip: "PEER IP",
                col_tap_ip: "IP Virtual",
                col_nat: "Estado NAT",
                col_peerid: "ID de Peer",
                col_multiaddr: "Multiaddr de Red",
                col_transport: "Transporte",
                col_uptime: "Tiempo Activo",
                col_rtt: "Latencia RTT",
                col_ip: "Dirección IP",
                col_mac: "Dirección MAC",
                col_rate: "Tasa en vivo",
                col_ip_attr: "Nodo / Atribución",
                col_target_peer: "ID de Peer Asociado",
                col_type: "Tipo",
                col_tx_traffic: "Tráfico Enviado",
                col_rx_traffic: "Tráfico Recibido",
                col_total_traffic: "Tráfico Total",
                col_pkts: "Paquetes",
                col_last_active: "Última Actividad",
                ip_scope_local: "TAP Local",
                ip_scope_peer: "Par de Malla",
                ip_scope_subnet: "Subred LAN",
                ip_scope_exit: "Pasarela de Salida",
                ip_scope_special: "Especial L2",
                ip_scope_wan: "Internet WAN",
                btn_disconnecting: "Desconectando...",
                topo_badge_peer: "Par de Malla",
                via: "vía",
                no_peers: "No hay nodos P2P activos conectados",
                no_arps: "Sin registros en la tabla ARP",
                no_ips: "Sin tráfico registrado por IP",
                no_macs: "Sin registros en la tabla MAC",
                col_mac_origin: "Origen",
                mac_origin_self: "IF del Peer",
                mac_origin_lan: "Reenvío LAN",
                mac_origin_self_tip: "La MAC de la interfaz TAP virtual propia de este peer (administrada localmente, empieza por 02:xx:…). Un peer sano tiene exactamente una.",
                mac_origin_lan_tip: "Un dispositivo en la LAN de este peer (por bridge/reenvío), no el peer en sí. Varios indican que el peer retransmite el tráfico de su LAN.",
                mac_lan_warn: "El peer {peer} está reenviando {n} dispositivo(s) de LAN —— normal cuando el peer hace bridge/reenvío de su LAN, no es un fallo.",
                retrieving_metrics: "Obteniendo métricas de enlace...",
                modal_title: "⚙️ Configuración de Nodo p2ptap",
                node_name_lbl: "Nombre del Nodo",
                strategy_lbl: "Estrategia de Transporte",
                psk_lbl: "Clave Precompartida (PSK)",
                psk_placeholder: "Vacío para red pública, clave para aislamiento cifrado",
                loglevel_lbl: "Nivel de Registro",
                obfs_lbl: "Modo de Ofuscación",
                obfs_fixed_size_lbl: "Tamaño Fijo de Paquete",
                obfs_fixed_size_desc: "MTU objetivo para relleno fijo (bytes)",
                bootstrap_lbl: "Nodos Bootstrap",
                section_identity: "Identidad del Nodo",
                section_identity_desc: "Nombre y configuración de cifrado de este nodo",
                node_name_desc: "Identificador legible para el panel de control",
                psk_desc: "Vacío para red pública, clave para aislamiento cifrado",
                section_transport: "Transporte y Registro",
                section_transport_desc: "Estrategia de enrutamiento y nivel de diagnóstico",
                strategy_desc: "Cómo se enrutan los paquetes a través de enlaces P2P",
                loglevel_desc: "Controla el nivel de detalle de la salida de consola",
                enable_mdns_lbl: "Habilitar detección de nodos LAN por mDNS",
                enable_mdns_desc: "Descubre automáticamente nodos en la misma LAN vía mDNS (solo red local)",
                cfg_disable_relay_lbl: "Desactivar Circuit Relay (diagnóstico)",
                cfg_disable_relay_desc: "Desactiva el cliente/servicio circuit-relay libp2p, AutoRelay y perforación DCUtR (requiere reinicio). No afecta al relé de superposición de p2ptap.",
                section_obfs: "Ofuscación de Tráfico",
                section_obfs_desc: "Relleno de paquetes para evitar huellas DPI",
                obfs_mode_desc: "Estrategia de relleno para tramas de datos P2P",
                section_bootstrap: "Nodos Bootstrap",
                section_bootstrap_desc: "Nodos de retransmisión iniciales para descubrimiento de red",
                bootstrap_placeholder: "Una multiaddr por línea",
                cfg_add_item: "➕ Añadir",
                cfg_list_empty: "Sin entradas.",
                drag_handle_tip: "Arrastrar para reordenar",
                drag_rule_tip: "Arrastrar para reordenar regla",
                move_up_tip: "Mover arriba",
                move_down_tip: "Mover abajo",
                acl_action_accept: "PERMITIR",
                acl_action_drop: "DENEGAR",
                acl_dir_both: "↔ Ambos",
                acl_dir_in: "↓ Entrante",
                acl_dir_out: "↑ Saliente",
                acl_proto_any: "Todos",
                acl_proto_tcp: "TCP",
                acl_proto_udp: "UDP",
                acl_proto_icmp: "ICMP",
                acl_no_rules_short: "Sin reglas ACL personalizadas (haga clic en „+ Añadir regla\" para crear una)",
                cancel_btn: "Cancelar",
                save_btn: "Guardar y Aplicar",
                save_success: "¡Configuración guardada correctamente!",
                cfg_needs_restart: "⚠️ Relay desactivado cambiado — reinicia p2ptap para aplicarlo.",
                save_failed: "Error al guardar: ",
                req_error: "Error en la solicitud de guardado: ",
                unnamed_node: "Nodo Sin Nombre",
                via_exit_node: "🚀 vía Nodo de Salida",
                via_exit_node_hint: "Tráfico enrutado a través del Nodo de Salida seleccionado",
                public_direct: "Directo (Público)",
                relayed_conn: "Relé",
                relay_only: "Solo Relay",
                not_configured: "No Configurado",
                log_count: "{n} Registros",
                log_listening: "Escuchando eventos de registro en vivo...",
                multiaddr_placeholder: "/ip4/1.2.3.4/udp/4001/quic-v1/p2p/12D3KooW...",
                exit_wan_placeholder: "auto (detectar automáticamente interfaz física de salida)",
                exit_status_title: "Estado en vivo",
                exit_status_inactive: "Ningún túnel Exit Node activo",
                exit_status_role_client: "Cliente",
                exit_status_role_server: "Servidor (ofrece salida)",
                exit_status_role_both: "Cliente + Servidor",
                exit_status_routing_via: "El tráfico se enruta a través de",
                exit_status_offering: "Ofreciendo salida a la malla",
                exit_status_peer: "Peer",
                exit_status_tap_ip: "TAP IP",
                exit_status_tap_ipv6: "TAP IPv6",
                subnets_placeholder: "ej. 192.168.1.0/24",
                allowed_peers_placeholder: "ej. * o 12D3KooW...",
                delete_rule: "🗑️ Eliminar",
                acl_peer_placeholder: "ID de Peer o *",
                acl_cidr_placeholder: "CIDR de destino o *",
                acl_port_placeholder: "Puerto / Rango",
                echo_test: "🧪 Prueba Echo",
                echo_test_hint: "💡 Haga clic en cualquier botón Echo Test para medir la latencia en una ruta Multiaddr específica.",
                test_all: "🧪 Probar Todo",
                speedtest_btn: "⚡ Prueba de Velocidad",
                test_echo: "⚡ Probar Echo",
                probing_text: "⏳ Sondeando...",
                probe_result: "🧪 {reachable}/{total} direcciones accesibles",
                probe_error: "🧪 Error de sondeo",
                probing_echo: "🚀 Sondeando flujo Echo vía {addr}...",
                probing_pathways_title: "🧪 Sondeando Rutas Multiaddr...",
                probing_pathways_desc: "Probando accesibilidad de flujo, RTT y tipos de transporte...",
                accept_subnets_lbl: "Aceptar subredes anunciadas de peers remotos",
                acl_default_action_lbl: "Política predeterminada para tráfico no coincidente",
                acl_flow_title: "Flujo secuencial de reglas:",
                acl_flow_hint_permit: "Lista de excepciones de permiso — estas reglas ALLOWean el tráfico coincidente, anulando la política DROP predeterminada.",
                acl_flow_hint_block: "Lista de excepciones de bloqueo — estas reglas DENYean el tráfico coincidente, anulando la política ACCEPT predeterminada.",
                acl_open_desc: "El firewall de malla está abierto (todo el tráfico P2P permitido)",
                acl_badge_open: "Malla abierta",
                acl_badge_active: "● Activo",
                acl_open_hint: "Active ACL en Configuración → Editor ACL para aplicar reglas.",
                acl_label_rules: "Reglas",
                acl_label_default: "Predeterminada",
                acl_label_accepted: "Aceptados",
                acl_label_dropped: "Descartados",
                acl_label_uptime: "Tiempo activo",
                acl_label_top_rules: "Reglas más coincididas",
                acl_label_recent_drops: "Rechazos recientes",
                acl_label_default_action: "predeterminada",
                acl_label_hits: "coincidencias",
                acl_label_more: "más",
                acl_default_accept: "ACCEPT (permitir)",
                acl_default_drop: "DROP (denegar)",
                strategy_redundant: "Doble envío (redundante)",
                strategy_fallback: "Conmutación por error",
                log_level_debug: "Depuración detallada",
                log_level_info: "Información estándar",
                log_level_warn: "Solo advertencias",
                log_level_error: "Solo errores",
                obfs_fixed: "Relleno de tamaño fijo",
                obfs_block: "Múltiplo de bloque",
                obfs_random: "Longitud aleatoria",
                obfs_dynamic: "Rango variable",
                obfs_auto: "Detección automática y cambio",
                acl_editor_title: "🛡️ Editor de reglas ACL",
                acl_no_rules: "Aún no hay reglas ACL personalizadas — añada una o elija una plantilla.",
                acl_test_title: "🧪 Probador de reglas ACL",
                acl_test_peer: "ID de peer de origen",
                acl_test_dir: "Dirección",
                acl_test_proto: "Protocolo",
                acl_test_dstip: "IP de destino",
                acl_test_dstport: "Puerto de destino",
                acl_test_allow: "PERMITIDO",
                acl_test_deny: "DENEGADO",
                acl_test_matched: "Regla coincidente",
                acl_test_default: "Ninguna regla coincidió — se aplicó la política predeterminada",
                acl_template_lbl: "Insertar plantilla…",
                acl_comment_placeholder: "Comentario / Descripción",
                close_btn: "Cerrar",
                acl_status_title: "🛡️ Firewall",
                active_exit_badge: "⚡ Puerta de enlace activa",
                active_pathway: "Ruta activa conectada actual",
                active_pathway_unknown: "Sin conexión activa",
                best_reachable_pathway: "Mejor candidato accesible (de la última prueba de multiaddr)",
                probe_unverified: "sin verificar",
                add_rule_btn: "➕ Añadir regla",
                adv_subnets_lbl: "Subredes anunciadas (CIDR, una por línea)",
                allowed_subnet_peers_lbl: "IDs de peers de subred permitidos (* para confiar en todos, una por línea)",
                badge_subnet_disabled: "⏸️ Desactivado",
                bandwidth_chart_title: "📈 Forma de onda de ancho de banda en vivo (Tx / Rx)",
                btn_cancel: "Cancelar",
                btn_close: "Cerrar",
                btn_connect_exit: "🚀 Conectar puerta de salida",
                exit_picker_hint: "Selecciona un par arriba para enrutar el tráfico",
                btn_disable_subnet: "🛑 Desactivar",
                btn_disconnect_exit: "⏹️ Desconectar salida",
                btn_enable_subnet: "▶️ Activar",
                btn_test_save_peer: "➕ Probar y guardar peer permanente",
                chosen_optimal: "🟢 Ruta óptima elegida",
                clear_exit_node_btn: "🛑 Disconnect Exit",
                col_candidate_path: "Ruta candidata",
                col_exit_egress: "Tráfico de salida del nodo de salida",
                col_inspector: "Inspector de decisiones",
                col_last_sync: "Última vez oído",
                col_rationale: "Motivo de decisión / rechazo",
                col_rtt_end: "RTT de extremo a extremo",
                col_status: "Estado",
                col_subnets: "Subredes anunciadas",
                col_sync_channel: "Canal de descubrimiento",
                col_tapmac: "MAC TAP",
                common_failed: "FALLÓ",
                common_idle: "inactivo",
                common_ok: "OK",
                common_peer: "Peer",
                common_read: "Leer",
                common_rtt: "RTT",
                common_unknown: "error desconocido",
                common_unknown_write_error: "error de escritura desconocido",
                common_write: "Escribir",
                copied_toast: "📋 ¡JSON de configuración copiado al portapapeles!",
                desc_arp: "Layer-2 Address Resolution",
                desc_broadcast: "Difusión L2 (incl. ARP)",
                desc_gateway: "Tunelizado vía nodo de salida",
                desc_icmp: "Sondas de red y keepalive",
                desc_multicast: "Multidifusión L2 (incl. mDNS)",
                desc_seq_sync: "Peers sincronizados · retransmisión / descartes de ventana",
                desc_tcp: "Flujos de bytes fiables",
                desc_udp: "Transporte de datagramas",
                direct_optimal_desc: "La latencia física directa es más rápida que cualquier ruta de retransmisión multi-salto candidata",
                direct_optimal_title: "P2P directo elegido (menor latencia)",
                disc_addrs: "Rutas de direcciones descubiertas",
                enable_acl_lbl: "Activar motor de firewall ACL",
                err_enter_multiaddr: "Introduzca una cadena Multiaddr válida",
                eval_table_title: "📊 Motor de enrutamiento Dijkstra - rutas candidatas evaluadas",
                exit_client_card_title: "🚀 Control de puerta de enlace de nodo de salida",
                exit_client_no_peers: "Actualmente no hay peers en línea que ofrezcan salida de nodo de salida",
                exit_client_status_active: "⚡ Enrutando todo el tráfico de internet vía nodo de salida",
                exit_client_status_inactive: "Ninguna puerta de salida activa (usando puerta de enlace predeterminada local)",
                exit_connected: "🚀 Exit gateway connected to ",
                exit_disconnected: "🛑 Puerta de salida desconectada",
                exit_enable_desc: "Enrutar el tráfico de internet a través de este peer",
                exit_enable_lbl: "Activar modo de puerta de enlace de nodo de salida",
                exit_nat_desc: "Traducción de dirección de origen para tráfico saliente",
                exit_nat_lbl: "Activar SNAT / Enmascaramiento (traducción de dirección de origen)",
                exit_node_badge: "🌐 Nodo de salida",
                exit_node_desc: "Enrutamiento de salida a internet vía este nodo",
                exit_node_title: "🌐 Configuración de puerta de enlace de nodo de salida",
                exit_wan_lbl: "Interfaz de salida WAN (p. ej. eth0 o auto)",
                inspect_btn: "🔍 Inspeccionar",
                inspector_title: "🧭 Inspector de decisiones de enrutamiento inteligente",
                lbl_arp_broadcast: "ARP Broadcast Frames",
                lbl_broadcast_pkts: "Paquetes de difusión",
                lbl_gateway_pkts: "Paquetes de puerta de enlace del nodo de salida",
                lbl_icmp_ping: "Eco ICMP (Ping)",
                lbl_multiaddr_str: "Cadena Multiaddr",
                lbl_multicast_pkts: "Paquetes de multidifusión",
                lbl_seq_sync: "Sinc. de secuencia y deduplicación",
                lbl_tcp_packets: "Paquetes de flujo TCP",
                lbl_udp_packets: "Paquetes de transporte UDP",
                logs_cleared: "Registros borrados.",
                matrix_dst: "Nodo de destino",
                matrix_hops: "Saltos",
                matrix_rtt: "Latencia RTT",
                matrix_src: "Nodo de origen",
                matrix_type: "Tipo de enlace",
                mesh_matrix_title: "🕸️ Matriz de calidad y latencia de malla",
                modal_add_static_desc: "Introduzca una Multiaddr P2P completa que contenga el destino /p2p/<PEER_ID>. La dirección se registrará de forma permanente en Peerstore con PermanentAddrTTL y se conectará automáticamente.",
                modal_add_static_title: "➕ Añadir Multiaddr de peer estático permanente",
                modal_diag_title: "⚡ Diagnóstico de ruta de peer y benchmark",
                nat_fallback_desc: "omite el aislamiento NAT simétrico cuando el enlace P2P directo no es alcanzable",
                no_matrix: "Sin rutas de peer en la matriz",
                no_peer_metas: "No se recibieron metadatos de peer vía peek-map / P2P",
                no_subnets: "No hay subredes anunciadas activas",
                dup_ip_conflicts_title: "⚠️ Conflictos de IP / subred duplicados",
                no_dup_ip_conflicts: "No se detectaron conflictos de IP ni subred duplicados",
                dup_winner: "Ganador",
                obfs_allow_switch_lbl: "Permitir cambio automático de modo",
                obfs_strict_key_lbl: "Negociación estricta de claves (PFS)",
                obfs_strict_key_desc: "Prohíbe retroceder a la clave de nodo de larga duración. Cada par de peers debe derivar su propio cifrado con una clave ECDH efímera de un solo uso; de lo contrario ese peer permanece en texto plano. Refuerza el aislamiento de claves por par.",
                obfs_auto_title: "🤖 Detección automática",
                obfs_block_size_desc: "Granularidad de alineación para modo bloque (bytes)",
                obfs_block_size_lbl: "Tamaño de alineación de bloque",
                obfs_dynamic_desc: "Rango mín–máx para tramas de tamaño variable",
                obfs_dynamic_lbl: "Rango de tamaño dinámico (bytes)",
                obfs_eval_interval_lbl: "Intervalo de evaluación",
                obfs_jitter_desc: "Random jitter to break fixed-size patterns (0=off)",
                obfs_jitter_lbl: "Rango de jitter (±bytes)",
                obfs_max_safe_desc: "PMTU safety threshold for obfuscated frames (bytes)",
                obfs_max_safe_lbl: "Max Safe Frame Size",
                obfs_threshold_lbl: "Umbral",
                packet_rate_title: "📊 Distribución de tasa de paquetes (Tx / Rx)",
                pcap_layer_frame: "Trama",
                pcap_layer_tree: "Análisis de protocolo",
                peer_meta_title: "📡 Monitor de metadatos de peer y descubrimiento Peek-Map",
                peer_traffic_title: "Peer Live Broadcasted Rate & Traffic",
                protocol_inspector_desc: "（Desglose de paquetes de capa 2/3/4 y estadísticas PPS en vivo）",
                protocol_inspector_title: "📊 Inspector de tráfico en vivo y protocolo Ethernet",
                proto_channels_title: "📡 Streams de Protocolo y Canales de Subsistema",
                th_stream_proto: "Protocolo / Canal",
                th_stream_peer: "Nodo Remoto",
                th_stream_direction: "Dirección",
                th_stream_transport: "Transporte & Multiaddr",
                th_stream_status: "Estado",
                search_streams_ph: "Buscar streams, protocolos, peers…",
                no_matching_streams: "No se encontraron streams de protocolo activos",
                no_channels: "No hay canales de protocolo activos",
                lbl_active_streams: "Streams",
                lbl_streams: "streams",
                dir_out: "Saliente ↑",
                dir_in: "Entrante ↓",
                stream_active: "Activo",
                channel_status_active: "Activo",
                channel_status_running: "En ejecución",
                channel_status_idle: "Inactivo",
                channel_status_standby: "En espera",
                channel_status_ready: "Listo",
                channel_status_open: "Modo abierto",
                category_sync: "Sincronización",
                category_routing: "Enrutamiento",
                category_pubsub: "PubSub",
                category_data: "Transferencia de datos",
                category_security: "Seguridad",
                category_transport: "Transporte",
                category_diagnostics: "Diagnóstico",
                category_discovery: "Descubrimiento",
                channel_seqsync_name: "Sincronización de secuencia (SeqSync)",
                channel_seqsync_desc: "Deduplicación de ventana y protección contra retransmisión",
                channel_lsa_name: "Enrutamiento de malla LSA",
                channel_lsa_desc: "Ruta más corta de Dijkstra",
                channel_peekmap_name: "Difusión de topología Peek-Map",
                channel_peekmap_desc: "Sincronización de topología Bootstrap",
                channel_data_name: "Ruta de datos TAP virtual",
                channel_data_proto: "Superposición Ethernet de capa 2",
                channel_auth_name: "Autenticación de malla PSK",
                channel_auth_desc: "Aislamiento de red de malla PSK",
                channel_dcutr_name: "Perforación de NAT DCUtR y Relay",
                channel_dcutr_desc: "Actualización a conexión directa",
                cipher_lbl: "Cifrado",

                rejected: "❌ Rechazado",
                relay_accel_active: "Aceleración de retransmisión activa",
                relay_accel_desc: "Algoritmo Dijkstra calculó ruta multi-salto vía",
                relay_chosen_title: "Retransmisión inteligente elegida",
                reset_view: "🎯 Restablecer vista",
                saved_latency: "ahorrado",
                section_acl_title: "🛡️ Editor de reglas ACL de malla P2P estilo ZeroTier",
                section_acl_desc: "Reglas de filtrado de tráfico por par",
                section_subnet_title: "🌐 Enrutador de subred y autorización",
                section_subnet_desc: "Anuncia subredes y autoriza qué pares pueden usarlas",
                set_as_exit_btn: "🚀 Set as Gateway",
                subnet_no_toggle: "No enrutable",
                subnet_routes_title: "🌐 Rutas de subred",
                badge_subnet_pending: "⛔ Autorización pendiente",
                target_node: "🎯 Nodo objetivo",
                toast_add_failed: "Error al añadir peer estático",
                toast_req_err: "Error de solicitud",
                toast_static_added: "¡Peer estático añadido y registrado permanentemente en Peerstore!",
                toast_subnet_disabled: "⏸️ Ruta de subred {cidr} desactivada en tiempo real",
                toast_subnet_enabled: "▶️ Ruta de subred {cidr} activada en tiempo real",
                toast_testing_adding: "Probando y añadiendo peer estático",
                topo_reset_layout: "📌 Reset Layout",
                topo_reset_zoom: "🔍 Reset View",
                topo_self_node: "Nodo propio",
                topo_standalone: "🌐 Nodo de malla independiente (esperando conexiones de peers P2P...)",
                topology_sub: "（Arrastre nodos para reposicionar | Desplazar para zoom | Doble clic para Ping）",
                topology_title: "🗺️ Mapa estelar de topología",
                troubleshoot_fail: "FALLÓ",
                troubleshoot_idle: "Seleccione un peer y haga clic en «Ejecutar diagnóstico completo» para solucionar problemas de conectividad.",
                troubleshoot_manual_input: "O introduzca el ID del peer manualmente...",
                troubleshoot_no_peer: "Seleccione o introduzca un peer para diagnosticar",
                troubleshoot_pass: "PASÓ",
                troubleshoot_run: "🔍 Ejecutar diagnóstico completo",
                troubleshoot_running: "EN EJECUCIÓN",
                troubleshoot_select_peer: "Seleccionar un peer para diagnosticar",
                troubleshoot_skip: "OMITIR",
                troubleshoot_step1: "Comprobación de interfaz TAP local",
                troubleshoot_step2: "Descubrimiento de peers y estado de conexión",
                troubleshoot_step3: "Sonda de conectividad de flujo libp2p",
                troubleshoot_step4: "Sonda de Multiaddr a nivel de transporte",
                linkcheck_title: "🔗 Verificación de enlace Multiaddr",
                linkcheck_desc: "Sonda profunda de transporte: multiaddr válido → DNS → TCP/QUIC → transporte libp2p → handshake Noise/TLS → coincidencia Peer ID → conexión.",
                linkcheck_input_ph: "Introduce una Multiaddr P2P completa, p. ej. /ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...",
                linkcheck_btn: "🔗 Ejecutar verificación",
                linkcheck_inline: "🔗 Verificar",
                linkcheck_inline_title: "Ejecutar diagnóstico de enlace de 7 etapas en esta multiaddr",
                linkcheck_running: "Ejecutando verificación de enlace…",
                linkcheck_no_input: "Introduce una multiaddr para verificar.",
                linkcheck_overall: "Resultado global",
                linkcheck_peer: "Peer objetivo",
                linkcheck_input: "Multiaddr probado",
                linkcheck_transport: "Transporte",
                linkcheck_resolved: "IPs resueltas",
                linkcheck_step1: "Multiaddr válido",
                linkcheck_step2: "Resolución DNS",
                linkcheck_step3: "TCP / QUIC establecido",
                linkcheck_step4: "Transporte libp2p",
                linkcheck_step5: "Handshake Noise / TLS",
                linkcheck_step6: "Coincidencia Peer ID",
                linkcheck_step7: "Conexión libp2p",
                troubleshoot_step5: "Análisis de ruta de enrutamiento overlay",
                troubleshoot_step6: "Comprobación de resolución ARP/NDP",
                troubleshoot_step7: "Comprobación de ACL y política de seguridad",
                troubleshoot_step8: "Autoprueba de lectura/escritura del dispositivo TAP",
                troubleshoot_step8_device: "Dispositivo",
                troubleshoot_step8_loopback_fail: "se esperaba loopback TAP, pero no se leyó ninguna trama",
                troubleshoot_step8_loopback_ok: "loopback verificado",
                troubleshoot_step8_request_fail: "Error en solicitud de autoprueba TAP",
                troubleshoot_step8_running: "Ejecutando autoprueba de lectura/escritura del dispositivo TAP…",
                troubleshoot_step8_stale_binary: "El endpoint /api/tap/selftest no respondió con JSON. El binario en ejecución probablemente está desactualizado — reconstruya y reinicie p2ptap.",
                troubleshoot_step8_unavailable: "Autoprueba TAP no disponible en este nodo.",
                troubleshoot_step8_wintun_noloop: "sin loopback — Wintun es un túnel L3, esperado",
                troubleshoot_step8_write_fail: "Ruta de escritura TAP FALLÓ.",
                troubleshoot_step9: "Prueba de reenvío de ruta de datos TAP de extremo a extremo",
                troubleshoot_step9_fail: "Prueba de reenvío TAP falló.",
                troubleshoot_step9_fail_detail: "Prueba de reenvío TAP falló — la ruta de datos TAP está rota aunque el eco (Paso 7) pasó.",
                troubleshoot_step9_hint: "Probablemente una ruta overlay unicast/relé rota o un problema de manejo de tramas TAP del peer. Revise la ruta de retransmisión y el dispositivo TAP del peer.",
                troubleshoot_step9_pass: "Trama TAP de ida y vuelta OK (solicitud eco ICMP → peer → respuesta eco ICMP).",
                troubleshoot_step9_request_fail: "Error en solicitud de prueba de reenvío TAP",
                troubleshoot_step9_running: "Inyectando una trama TAP (solicitud eco ICMP) en el overlay hacia la IP TAP del peer…",
                troubleshoot_step9_sent: "Enviado",
                troubleshoot_title: "🔧 Solucionador de conectividad P2P",
                troubleshoot_warn: "AVISO",
                unreachable: "Inalcanzable",
                view_addr: "Ver Multiaddr",
                vs_direct: "en comparación con la ruta directa",
                col_encryption: "Cifrado",
                topo_legend_direct_fast: "● Directo (<30ms)",
                topo_legend_direct_slow: "● Directo (30-100ms)",
                topo_legend_relay: "● Relay de tránsito (ámbar) — los pares relayados cuelgan debajo",
                topo_legend_flow: "💧 Densidad de flujo = tasa real TX/RX (los enlaces inactivos no fluyen)",
                topo_badge_transit: "🌉 Switch de tránsito",
                topo_badge_exit_server: "🚪 Servidor de salida",
                topo_via: "vía",
                topo_link_idle: "inactivo",
                topo_summary_nodes: "Nodos",
                topo_summary_direct: "Directo",
                topo_summary_relayed: "Relayados",
                topo_summary_relays: "Relays de tránsito",
                topo_summary_thru: "Throughput de malla",
                topo_summary_gw: "Paquetes de gateway",
                topo_summary_boots: "Bootstrap",
                topo_summary_static: "Pares estáticos",
                topo_summary_clusters: "Clústeres",
                topo_filter_remote: "Entre clústeres",
                topo_legend_boot: "● Nodo bootstrap (púrpura)",
                topo_legend_overlay: "◆ Relay de overlay (línea larga)",
                topo_badge_boot: "Bootstrap",
                topo_badge_static: "Estático",
                topo_tt_role_boot: "Nodo bootstrap",
                topo_tt_role_static: "Par estático",
                topo_tt_cluster: "Clúster:",
                topo_tt_boot_hops: "Saltos boot:",
                topo_tt_transport_path: "Ruta de transporte:",
                topo_tt_relay_hop: "Salto relay:",
                topo_tt_enc: "Cifrado:",
                topo_tt_conn: "Estado de conexión:",
                topo_tt_jitter: "Jitter:",
                topo_tt_loss: "Pérdida:",
                topo_tt_version: "Versión:",
                topo_tt_since: "Conectado:",
                topo_tt_geo: "Geo:",
                topo_tt_total: "Total (Tx/Rx):",
                topo_tt_route_via: "Ruta:",
                topo_tt_blackhole: "Agujero negro Rx (desfase dedup)",
                topo_tt_circuit_relay: "Relay de circuito v2",
                topo_tt_dedup_window: "Ventana dedup:",
                topo_tt_direct_link: "Enlace P2P directo",
                topo_tt_dup_drops: "Caídas duplicadas:",
                topo_tt_healthy: "Saludable",
                topo_tt_ipv4: "IPv4 virtual:",
                topo_tt_ipv6: "IPv6 virtual:",
                topo_tt_link_integrity: "Integridad del enlace:",
                topo_tt_live_rate: "Tasa en vivo:",
                topo_tt_local_host: "Host local",
                topo_tt_optimal_route: "Ruta óptima:",
                topo_tt_os_arch: "SO / Arquitectura:",
                topo_tt_peer_id: "ID de par:",
                topo_tt_route: "Ruta:",
                topo_tt_route_gain: "Ganancia de ruta:",
                topo_tt_rtt: "Latencia RTT:",
                topo_tt_seq: "Seq (Tx/Rx):",
                topo_tt_tap_ip: "IP del par:",
                topo_tt_transit_relay: "Relay de tránsito",
                topo_tt_transport: "Transporte:",
                topo_tt_uptime: "Tiempo activo:",
            },
            "fr": {
                default_node_name: "Nœud VPN P2P TAP",
                login_title: "🔐 Connexion au tableau de bord P2P TAP",
                login_subtitle: "Ce tableau de bord est protégé. Saisissez votre jeton d'accès pour continuer.",
                login_token_label: "Jeton d'accès",
                login_token_placeholder: "Collez le jeton du journal de démarrage ou config (webui.auth_token)",
                login_btn: "Se connecter",
                login_error: "Jeton invalide ou requête échouée. Veuillez réessayer.",
                login_hint: "Le jeton est stocké localement dans votre navigateur et envoyé en en-tête Bearer.",
                speed_test: "⚡ Test de Vitesse P2P",
                btn_add_static_peer: "➕ Ajouter un pair statique",
                pcap_title: "🔬 Capture de Paquets",
                pcap_stopped: "Arrêté",
                pcap_running: "● Capture en cours",
                pcap_start: "▶️ Démarrer",
                pcap_pause: "⏸️ Pause",
                pcap_clear: "🗑️ Effacer",
                pcap_autoscroll: "Défilement auto",
                pcap_stream_live: "Flux temps réel (WebSocket)",
                pcap_stream_connecting: "Connexion…",
                pcap_stream_polling: "Sondage en repli (flux indisponible)",
                pcap_stream_off: "Flux déconnecté",
                pcap_stream_dropped: "trames perdues (client trop lent)",
                log_stream_live: "Flux temps réel (WebSocket)",
                log_stream_connecting: "Connexion…",
                log_stream_polling: "Sondage en repli (flux indisponible)",
                log_stream_off: "Flux déconnecté",
                log_stream_dropped: "journaux perdus (client trop lent)",
                pcap_desc: "Capture les trames Ethernet brutes émises/reçues sur la NIC virtuelle TAP locale (MAC src/dst, protocole, IP, hex). <span class=\"tx-tag\">tx</span> = émis par cet hôte, <span class=\"rx-tag\">rx</span> = reçu. <span class=\"tx-tag\">Cliquez sur une ligne</span> pour voir les détails complets et le dump hex.",
                pcap_empty: "Aucune donnée. Cliquez sur « Démarrer » pour capturer le trafic TAP local.",
                pcap_click_hint: "Cliquez pour voir les détails complets",
                pcap_dup_repeat: "Trame répétée — identique à la ligne précédente (réémission mDNS / multicast)",
                pcap_dup_repeat_row: "Trame répétée — payload identique à la ligne précédente. Comportement normal du mDNS / multicast, pas un doublon de rendu.",
                pcap_modal_title: "🔬 Détails du Paquet",
                pcap_modal_raw: "Hex complet (raw frame)",
                pcap_copy_hex: "📋 Copier Hex",
                pcap_dir_tx: "Émis par l'hôte (tx)",
                pcap_dir_rx: "Reçu (rx)",
                pcap_f_seq: "Seq",
                pcap_f_time: "Heure",
                pcap_f_dir: "Direction",
                pcap_f_srcmac: "MAC Source",
                pcap_f_dstmac: "MAC Destination",
                pcap_f_etype: "EtherType",
                pcap_f_proto: "Protocole",
                pcap_f_vlan: "VLAN ID",
                pcap_f_l4proto: "Protocole L4",
                pcap_f_srcip: "IP Source",
                pcap_f_dstip: "IP Destination",
                pcap_f_srcport: "Port Source",
                pcap_f_dstport: "Port Destination",
                pcap_f_tcpflags: "Drapeaux TCP",
                pcap_f_tcpseq: "Séquence TCP",
                pcap_f_tcpwin: "Fenêtre TCP",
                pcap_f_dns: "Requête DNS",
                pcap_f_sni: "TLS SNI",
                pcap_f_ttl: "TTL",
                pcap_f_arpop: "Op ARP",
                pcap_f_arpsmac: "MAC Émetteur ARP",
                pcap_f_arpdmac: "MAC Cible ARP",
                pcap_f_frompeer: "Du Peer",
                pcap_f_topeer: "Vers Peer",
                pcap_f_len: "Longueur Trame",
                pcap_f_info: "Résumé Protocole",
                pcap_col_seq: "#",
                pcap_col_time: "Heure",
                pcap_col_dir: "Dir",
                pcap_col_srcmac: "MAC Source",
                pcap_col_dstmac: "MAC Dest.",
                pcap_col_etype: "Type",
                pcap_col_proto: "Proto",
                pcap_col_srcip: "IP Source",
                pcap_col_dstip: "IP Dest.",
                pcap_col_ports: "Ports",
                pcap_col_flags: "Drapeaux",
                pcap_col_dns: "DNS",
                pcap_col_sni: "SNI",
                pcap_col_frompeer: "Depuis Peer",
                pcap_col_topeer: "Vers Peer",
                pcap_col_len: "Long.",
                pcap_col_info: "Résumé",
                pcap_col_hex: "Hex (64 premiers B)",
                share_config: "📲 Partager et Exporter",
                terminal_title: "📟 Console de Journaux en Direct",
                auto_scroll: "📜 Défilement Auto: ON",
                auto_scroll_off: "📜 Défilement Auto: OFF",
                clear_logs: "🗑️ Effacer",
                pause_logs: "⏸️ Pause",
                resume_logs: "▶️ Reprendre",
                log_paused_badge: "⏸ En pause",
                copy_logs: "📋 Copier",
                logs_copied: "📋 Journaux copiés dans le presse-papiers !",
                logs_empty_copy: "Rien à copier pour l'instant.",
                copy_failed: "Échec de la copie.",
                speedtest_title: "⚡ Test de Bande Passante et Latence P2P",
                select_target_peer: "Sélectionner le Nœud Cible",
                mbps_label: "Mbps (Débit P2P)",
                rtt_avg: "RTT Moyen",
                jitter_lbl: "Jitter",
                quality_lbl: "Qualité",
                start_test_btn: "🚀 Démarrer le Test",
                share_title: "📲 Partager et Exporter la Configuration",
                share_desc: "Scannez le code QR ou exportez la configuration JSON pour déployer des nœuds.",
                copy_json: "📋 Copier le JSON",
                download_json: "💾 Télécharger le Fichier",
                col_geo: "Localisation Géo",
                col_conn_time: "Temps Connecté",
                col_last_active: "Dernière Activité",
                col_jitter_loss: "Jitter / Perte",
                col_status: "État de connexion",
                col_return_path: "Chemin de retour",
                conn_ok: "Connecté",
                conn_relay_ok: "Relais OK",
                conn_connecting: "Connexion",
                conn_proto_mismatch: "Protocole incompatible",
                conn_obf_failed: "Échec déchiffrement",
                conn_unreachable: "Injoignable",
                return_ok: "Retour OK",
                return_dead: "Retour coupé",
                return_idle: "Retour inconnu",
                col_actions: "Actions",
                topo_tx: "Route Aller (Tx ➔)",
                topo_rx: "Route Retour (Rx ⬅️)",
                topo_relay: "Relais Multi-Sauts",
                peer_id_lbl: "ID de Pair",
                strategy_best_path: "MEILLEUR_CHEMIN",
                strategy_low_latency: "FAIBLE_LATENCE",
                strategy_high_bandwidth: "HAUTE_BANDE_PASSANTE",
                search_placeholder: "Rechercher…",
                prev_page: "‹ Précédent",
                next_page: "Suivant ›",
                per_page: "Par page",
                no_match: "Aucune correspondance",
                sys_health_title: "💻 Santé du Système et du Runtime",
                badge_active: "Actif",
                lbl_heap: "Alloc. Heap / Sys:",
                lbl_goroutines: "Goroutines:",
                lbl_gc_runs: "Exécutions GC:",
                lbl_process_uptime: "Temps de Fonctionnement:",
                lbl_heap_inuse: "Tas en Usage:",
                lbl_heap_objects: "Objets Tas Vivants:",
                lbl_stack_inuse: "Usage Pile Goroutines:",
                lbl_next_gc: "Prochain GC @:",
                lbl_last_gc_pause: "Dernière Pause GC:",
                lbl_gc_cpu: "Fraction CPU GC:",
                lbl_gomaxprocs: "GOMAXPROCS:",
                lbl_cpu_cores: "Cœurs CPU:",
                security_title: "🛡️ Statut de Sécurité et Chiffrement",
                badge_protected: "Protégé",
                lbl_psk_status: "Statut Maillage PSK:",
                lbl_traffic_obfs: "Obfuscation de Trafic:",
                lbl_id_fingerprint: "Empreinte d'Identité:",
                lbl_autonat_reach: "Accessibilité AutoNAT:",
                lbl_per_peer_enc: "Chiffrement par Pair:",
                sec_copy: "Copier",
                sec_copied: "Copié",
                sec_peer_title: "Détails du Chiffrement du Pair",
                sec_peer_id: "ID du Pair",
                sec_peer_algo: "Chiffre",
                sec_peer_pfs: "Confidentialité Persistance",
                sec_yes: "Oui",
                sec_no: "Non",
                sec_peer_tx_fp: "Empreinte de Clé TX (SHA-256, 8 premiers hex)",
                sec_peer_rx_fp: "Empreinte de Clé RX (SHA-256, 8 premiers hex)",
                sec_peer_pfs_eph: "Empreinte de Clé Publique ECDH Éphémère",
                sec_peer_epoch_local: "Époque de Handshake Locale",
                sec_peer_epoch_peer: "Époque de Handshake du Pair",
                sec_peer_copy: "Copier",
                sec_peer_close: "Fermer",
                sec_click_details: "Cliquer pour les détails et copier",
                no_peers_enc: "Aucun pair connecté",
                protocol_dist_title: "🥧 Distribution du Trafic de Protocole",
                public_unencrypted: "Public (Non Chiffré)",
                encrypted_overlay: "Maillage Chiffré (Noise/PSK)",
                disabled: "Désactivé",
                online: "EN LIGNE (Actualisation 2s)",
                refresh: "🔄 Actualiser",
                settings: "⚙️ Paramètres",
                tap_ipv4: "Adresse IPv4 Virtuelle",
                tap_ipv4_sub: "Ethernet Virtuel Couche-2",
                tap_ipv6: "Adresse IPv6 Virtuelle",
                tap_ipv6_sub: "Support Natif Double-Pile",
                tx_bytes: "Données Envoyées (TX)",
                rx_bytes: "Données Reçues (RX)",
                pkts_total: "Total paquets: ",
                dedup_count: "Paquets Dédupliqués",
                dedup_sub: "Filtrage des Doublons Multi-liens",
                topology_mesh: "🕸️ Maillage Topologique P2P Interactif",
                topo_filter_label: "Filtrer :",
                topo_filter_all: "Tous",
                topo_filter_direct: "Direct",
                topo_filter_relayed: "Relayé",
                topo_click_hint: "Cliquez sur un nœud pour voir les détails et surligner son chemin",
                topo_clear_sel: "Fermer",
                ping_tool: "📡 Diagnostic Réseau P2P (Ping & Traceroute)",
                troubleshoot_title: "🔧 Outil de Dépannage de Connectivité P2P",
                troubleshoot_select_peer: "Sélectionner un pair à diagnostiquer",
                troubleshoot_manual_input: "Ou entrer l'ID du pair manuellement...",
                troubleshoot_run: "🔍 Exécuter un diagnostic complet",
                troubleshoot_running: "Exécution du diagnostic en cours...",
                troubleshoot_step1: "Vérification de l'interface TAP locale",
                troubleshoot_step2: "Découverte des pairs et statut de connexion",
                troubleshoot_step3: "Sonde de connectivité des flux libp2p",
                troubleshoot_step4: "Sonde Multiaddr au niveau transport",
                linkcheck_title: "🔗 Test de liaison Multiaddr",
                linkcheck_desc: "Sonde transport approfondie : multiaddr valide → DNS → TCP/QUIC → transport libp2p → handshake Noise/TLS → correspondance Peer ID → connexion.",
                linkcheck_input_ph: "Saisir une Multiaddr P2P complète, ex. /ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...",
                linkcheck_btn: "🔗 Lancer le test",
                linkcheck_inline: "🔗 Vérifier",
                linkcheck_inline_title: "Exécuter le diagnostic de liaison en 7 étapes sur cette multiaddr",
                linkcheck_running: "Test de liaison en cours…",
                linkcheck_no_input: "Veuillez saisir une multiaddr à tester.",
                linkcheck_overall: "Résultat global",
                linkcheck_peer: "Pair cible",
                linkcheck_input: "Multiaddr testée",
                linkcheck_transport: "Transport",
                linkcheck_resolved: "IP résolues",
                linkcheck_step1: "Multiaddr valide",
                linkcheck_step2: "Résolution DNS",
                linkcheck_step3: "TCP / QUIC établi",
                linkcheck_step4: "Transport libp2p",
                linkcheck_step5: "Handshake Noise / TLS",
                linkcheck_step6: "Correspondance Peer ID",
                linkcheck_step7: "Connexion libp2p",
                troubleshoot_step5: "Analyse des chemins de routage superposés",
                troubleshoot_step6: "Vérification de la résolution ARP/NDP",
                troubleshoot_step7: "Vérification des politiques de sécurité et pare-feu ACL",
                troubleshoot_pass: "RÉUSSI",
                troubleshoot_fail: "ÉCHOUÉ",
                troubleshoot_warn: "AVERTISSEMENT",
                troubleshoot_skip: "IGNORÉ",
                troubleshoot_step8: "Auto-test de lecture/écriture du périphérique TAP",
                troubleshoot_step8_running: "Exécution de l'auto-test de lecture/écriture TAP…",
                troubleshoot_step8_unavailable: "L'auto-test TAP n'est pas disponible sur ce nœud.",
                troubleshoot_step8_stale_binary: "Le point de terminaison /api/tap/selftest n'a pas répondu en JSON. Le binaire en cours d'exécution est probablement obsolète — recompilez et redémarrez p2ptap.",
                troubleshoot_step8_write_fail: "Le chemin d'écriture TAP a ÉCHOUÉ.",
                troubleshoot_step8_device: "Périphérique",
                troubleshoot_step8_wintun_noloop: "pas de bouclage — Wintun est un tunnel L3, attendu",
                troubleshoot_step8_loopback_ok: "bouclage vérifié",
                troubleshoot_step8_loopback_fail: "bouclage TAP attendu, mais aucune trame lue en retour",
                troubleshoot_step8_request_fail: "La requête d'auto-test TAP a échoué",
                troubleshoot_step9: "Test de transfert de bout en bout du chemin de données TAP",
                troubleshoot_step9_running: "Injection d'une trame TAP (ICMP echo request) dans l'overlay vers l'IP TAP du pair…",
                troubleshoot_step9_pass: "Aller-retour de la trame TAP OK (ICMP echo request → pair → ICMP echo reply).",
                troubleshoot_step9_sent: "Envoyé",
                troubleshoot_step9_fail: "Le test de transfert TAP a échoué.",
                troubleshoot_step9_fail_detail: "Le test de transfert TAP a échoué — le chemin de données TAP est cassé même si l'echo (Étape 7) passe.",
                troubleshoot_step9_hint: "Probablement un chemin unicast/relais overlay cassé ou un problème de gestion des trames TAP côté pair. Vérifiez le chemin de relais et le périphérique TAP du pair.",
                troubleshoot_step9_request_fail: "La requête de test de transfert TAP a échoué",
                common_ok: "OK",
                common_failed: "ÉCHEC",
                common_idle: "inactif",
                common_write: "Écriture",
                common_read: "Lecture",
                common_unknown_write_error: "erreur d'écriture inconnue",
                troubleshoot_no_peer: "Veuillez sélectionner ou entrer un pair à diagnostiquer",
                troubleshoot_idle: "Sélectionnez un pair et cliquez sur 'Exécuter un diagnostic complet' pour commencer le dépannage de la connectivité.",
                run_ping: "🚀 Lancer le Test Ping",
                run_trace: "🔍 Lancer Traceroute",
                ping_placeholder: "ex. 10.0.0.2 ou 12D3KooW...",
                active_peers: "⚡ Nœuds P2P Actifs",
                routes_table: "🛣️ Table de Routage Intelligente P2P Overlay",
                stat_total_routes: "Total des Routes Calculées",
                stat_relayed_routes: "Voies Accélérées par Relais",
                stat_max_savings: "Réduction Max. de Latence",
                stat_mesh_health: "Santé de la Topologie",
                arp_table: "📋 Table des Voisins ARP / NDP Virtuelle",
                ip_analytics: "📊 Analyse du Trafic par IP sur 24h",
                mac_table: "🔀 Table MAC du Commutateur Virtuel",
                no_routes: "Aucune route calculée",
                col_dest: "Nœud Destinataire",
                col_hops: "Sauts",
                col_optimal_path: "Parcours Visuel",
                col_total_rtt: "RTT Optimal",
                col_direct_rtt: "RTT Direct",
                col_optimization: "Accélération",
                col_route_status: "Statut de Route",
                col_nodename: "Nom du Nœud",
                col_osarch: "OS / Arch",
                col_tapip: "PEER IP",
                col_tap_ip: "IP Virtuelle",
                col_nat: "Statut NAT",
                col_peerid: "ID Peer",
                col_multiaddr: "Multiaddr Réseau",
                col_transport: "Transport",
                col_uptime: "Temps d'activité",
                col_rtt: "Latence RTT",
                col_mac: "Adresse MAC",
                col_target_peer: "ID Peer Associé",
                no_peers: "Aucun nœud P2P actif connecté",
                no_macs: "Aucune donnée dans la table MAC",
                col_mac_origin: "Source",
                mac_origin_self: "IF du Pair",
                mac_origin_lan: "Transfert LAN",
                mac_origin_self_tip: "La MAC de l'interface TAP virtuelle propre de ce pair (administrée localement, commence par 02:xx:…). Un pair sain n'en a qu'une.",
                mac_origin_lan_tip: "Un appareil sur le LAN de ce pair (via bridge/transfert), pas le pair lui-même. Plusieurs entrées signifient que le pair relaie le trafic de son LAN.",
                mac_lan_warn: "Le pair {peer} transmet {n} appareil(s) LAN —— normal quand le pair bridge/transmet son LAN, pas un défaut.",
                retrieving_metrics: "Récupération des métriques...",
                modal_title: "⚙️ Configuration du Nœud p2ptap",
                node_name_lbl: "Nom du Nœud",
                strategy_lbl: "Stratégie de Transport",
                psk_lbl: "Clé Pré-partagée (PSK)",
                psk_placeholder: "Vide pour réseau public, clé pour isolation chiffrée",
                loglevel_lbl: "Niveau de Journal",
                obfs_lbl: "Mode d'Offuscation",
                obfs_fixed_size_lbl: "Taille Fixe de Paquet",
                obfs_fixed_size_desc: "MTU cible pour le remplissage fixe (octets)",
                bootstrap_lbl: "Nœuds Bootstrap",
                section_identity: "Identité du Nœud",
                section_identity_desc: "Nom et paramètres de chiffrement de ce nœud",
                node_name_desc: "Identifiant lisible pour le tableau de bord",
                psk_desc: "Vide pour réseau public, clé pour isolation chiffrée",
                section_transport: "Transport & Journalisation",
                section_transport_desc: "Stratégie de routage et verbosité du diagnostic",
                strategy_desc: "Comment les paquets sont routés via les liaisons P2P",
                loglevel_desc: "Contrôle la verbosité de la sortie console",
                enable_mdns_lbl: "Activer la découverte de nœuds LAN via mDNS",
                enable_mdns_desc: "Découvre automatiquement les nœuds du même LAN via mDNS (réseau local uniquement)",
                cfg_disable_relay_lbl: "Désactiver Circuit Relay (diagnostic)",
                cfg_disable_relay_desc: "Désactive le client/service circuit-relay libp2p, AutoRelay et perforation DCUtR (redémarrage requis). N'affecte pas le relais propre à p2ptap.",
                section_obfs: "Offuscation du Trafic",
                section_obfs_desc: "Remplissage de paquets contre l'empreinte DPI",
                obfs_mode_desc: "Stratégie de remplissage pour les trames de données P2P",
                section_bootstrap: "Nœuds Bootstrap",
                section_bootstrap_desc: "Nœuds de relais initiaux pour la découverte du réseau",
                bootstrap_placeholder: "Une multiaddr par ligne",
                cfg_add_item: "➕ Ajouter",
                cfg_list_empty: "Aucune entrée.",
                drag_handle_tip: "Glisser pour réorganiser",
                drag_rule_tip: "Glisser pour réorganiser la règle",
                move_up_tip: "Monter",
                move_down_tip: "Descendre",
                acl_action_accept: "AUTORISER",
                acl_action_drop: "REFUSER",
                acl_dir_both: "↔ Les deux",
                acl_dir_in: "↓ Entrant",
                acl_dir_out: "↑ Sortant",
                acl_proto_any: "TOUS",
                acl_proto_tcp: "TCP",
                acl_proto_udp: "UDP",
                acl_proto_icmp: "ICMP",
                acl_no_rules_short: "Aucune règle ACL personnalisée (cliquez sur „+ Ajouter une règle\" pour en créer une)",
                exit_node_title: "🌐 Paramètres du Nœud de Sortie (Exit Node)",
                exit_enable_lbl: "Activer le Mode Nœud de Sortie (Exit Node)",
                exit_nat_lbl: "Activer SNAT / Masquerade (Traduction d'adresse source)",
                exit_wan_lbl: "Interface Réseau Physique (WAN)",
                exit_node_badge: "🌐 Nœud de Sortie",
                set_as_exit_btn: "🚀 Définir Passerelle",
                clear_exit_node_btn: "🛑 Déconnecter Passerelle",
                active_exit_badge: "⚡ Passerelle Active",
                exit_connected: "🚀 Passerelle de sortie connectée à ",
                exit_disconnected: "🛑 Passerelle de sortie déconnectée",
                peer_traffic_title: "Débit en direct et trafic du nœud",
                topo_reset_layout: "📌 Disposition",
                topo_reset_zoom: "🔍 Réinitialiser Vue",
                bandwidth_chart_title: "📈 Graphique de bande passante en direct",
                mesh_matrix_title: "🕸️ Matrice de qualité et latence du réseau",
                matrix_src: "Nœud source",
                matrix_dst: "Nœud destination",
                matrix_rtt: "Latence RTT",
                matrix_hops: "Sauts (Hops)",
                matrix_type: "Type de lien",
                no_matrix: "Aucune donnée de matrice",
                subnet_routes_title: "🌐 Routes de sous-réseau",
                no_subnets: "Aucun sous-réseau annoncé reçu",
                dup_ip_conflicts_title: "⚠️ Conflits IP / sous-réseau en doublon",
                no_dup_ip_conflicts: "Aucun conflit d'IP ni de sous-réseau en doublon détecté",
                dup_winner: "Gagnant",
                exit_client_card_title: "🚀 Contrôle du Nœud de Sortie",
                exit_client_status_active: "⚡ Routage de tout le trafic Internet via le nœud de sortie",
                exit_client_status_inactive: "Aucune passerelle de sortie active (utilisation de la passerelle par défaut locale)",
                exit_client_no_peers: "Aucun pair en ligne ne propose de nœud de sortie actuellement",
                btn_connect_exit: "🚀 Connecter la passerelle",
                exit_picker_hint: "Sélectionnez un pair ci-dessus pour acheminer le trafic",
                btn_disconnect_exit: "⏹️ Déconnecter la passerelle",
                btn_enable_subnet: "▶️ Activer",
                btn_disable_subnet: "🛑 Désactiver",
                badge_subnet_disabled: "⏸️ Désactivé",
                badge_subnet_pending: "⛔ Autorisation en attente",
                subnet_no_toggle: "Non routable",
                toast_subnet_enabled: "▶️ Route de sous-réseau {cidr} activée en temps réel",
                toast_subnet_disabled: "⏸️ Route de sous-réseau {cidr} désactivée en temps réel",
                acl_status_title: "🛡️ Pare-feu",
                acl_open_desc: "Pare-feu ouvert (Tout le trafic P2P autorisé)",
                acl_badge_open: "Maillage ouvert",
                acl_badge_active: "● Actif",
                acl_open_hint: "Activez l'ACL dans Paramètres → Éditeur ACL pour appliquer les règles.",
                acl_label_rules: "Règles",
                acl_label_default: "Par défaut",
                acl_label_accepted: "Acceptés",
                acl_label_dropped: "Rejetés",
                acl_label_uptime: "Durée",
                acl_label_top_rules: "Règles les plus matchées",
                acl_label_recent_drops: "Rejets récents",
                acl_label_default_action: "par défaut",
                acl_label_hits: "occurrences",
                acl_label_more: "plus",
                acl_default_accept: "ACCEPT (autoriser)",
                acl_default_drop: "DROP (refuser)",
                strategy_redundant: "Double envoi (redondant)",
                strategy_fallback: "Basculement (secours)",
                log_level_debug: "Débogage détaillé",
                log_level_info: "Informations standard",
                log_level_warn: "Avertissements uniquement",
                log_level_error: "Erreurs uniquement",
                obfs_fixed: "Remplissage taille fixe",
                obfs_block: "Multiple de bloc",
                obfs_random: "Longueur aléatoire",
                obfs_dynamic: "Plage variable",
                obfs_auto: "Détection auto et basculement",
                acl_editor_title: "🛡️ Éditeur de règles ACL",
                acl_no_rules: "Pas encore de règles ACL personnalisées — ajoutez-en une ou choisissez un modèle.",
                acl_test_title: "🧪 Testeur de règles ACL",
                acl_test_peer: "ID du pair source",
                acl_test_dir: "Direction",
                acl_test_proto: "Protocole",
                acl_test_dstip: "IP de destination",
                acl_test_dstport: "Port de destination",
                acl_test_allow: "AUTORISÉ",
                acl_test_deny: "REFUSÉ",
                acl_test_matched: "Règle correspondante",
                acl_test_default: "Aucune règle ne correspond — application de la politique par défaut",
                acl_template_lbl: "Insérer un modèle…",
                acl_comment_placeholder: "Commentaire / Description",
                close_btn: "Fermer",
                cancel_btn: "Annuler",
                save_btn: "Enregistrer & Appliquer",
                save_success: "Configuration enregistrée avec succès !",
                cfg_needs_restart: "⚠️ Désactivation du relay modifiée — redémarrez p2ptap pour l'appliquer.",
                save_failed: "Échec de l'enregistrement : ",
                req_error: "Erreur de requête d'enregistrement : ",
                unnamed_node: "Nœud Sans Nom",
                via_exit_node: "🚀 via Nœud de Sortie",
                via_exit_node_hint: "Trafic routé via la passerelle du Nœud de Sortie sélectionné",
                public_direct: "Direct (Public)",
                relayed_conn: "Relais",
                relay_only: "Relais seul",
                not_configured: "Non Configuré",
                log_count: "{n} Journaux",
                log_listening: "À l'écoute des événements de journal en direct...",
                multiaddr_placeholder: "/ip4/1.2.3.4/udp/4001/quic-v1/p2p/12D3KooW...",
                exit_wan_placeholder: "auto (détection automatique de l'interface de sortie physique)",
                exit_status_title: "Statut en direct",
                exit_status_inactive: "Aucun tunnel Exit Node actif",
                exit_status_role_client: "Client",
                exit_status_role_server: "Serveur (offre une sortie)",
                exit_status_role_both: "Client + Serveur",
                exit_status_routing_via: "Le trafic passe par",
                exit_status_offering: "Offre une sortie au mesh",
                exit_status_peer: "Pair",
                exit_status_tap_ip: "TAP IP",
                exit_status_tap_ipv6: "TAP IPv6",
                subnets_placeholder: "ex. 192.168.1.0/24",
                allowed_peers_placeholder: "ex. * ou 12D3KooW...",
                delete_rule: "🗑️ Supprimer",
                acl_peer_placeholder: "ID de pair ou *",
                acl_cidr_placeholder: "CIDR cible ou *",
                acl_port_placeholder: "Port / Plage",
                echo_test: "🧪 Test Echo",
                echo_test_hint: "💡 Cliquez sur n'importe quel bouton Test Echo pour mesurer la latence sur un chemin Multiaddr spécifique.",
                test_all: "🧪 Tester Tout",
                speedtest_btn: "⚡ Test de Vitesse",
                test_echo: "⚡ Tester Echo",
                probing_text: "⏳ Sondage en cours...",
                probe_result: "🧪 {reachable}/{total} adresses joignables",
                probe_error: "🧪 Erreur de sondage",
                probing_echo: "🚀 Sondage du flux Echo via {addr}...",
                probing_pathways_title: "🧪 Sondage des chemins Multiaddr...",
                probing_pathways_desc: "Test de l'accessibilité du flux, RTT et types de transport...",
                accept_subnets_lbl: "Accepter les sous-réseaux annoncés par les pairs distants",
                acl_default_action_lbl: "Politique par défaut pour le trafic non correspondant",
                acl_flow_title: "Flux de règles séquentielles :",
                acl_flow_hint_permit: "Liste d'exceptions de permission — ces règles ALLOWent le trafic correspondant malgré la politique DROP par défaut.",
                acl_flow_hint_block: "Liste d'exceptions de blocage — ces règles DENYent le trafic correspondant malgré la politique ACCEPT par défaut.",
                active_pathway: "Chemin actif connecté actuel",
                active_pathway_unknown: "Aucune connexion active",
                best_reachable_pathway: "Meilleur candidat joignable (depuis le dernier test multiaddr)",
                probe_unverified: "non vérifié",
                add_rule_btn: "➕ Ajouter une règle",
                adv_subnets_lbl: "Sous-réseaux annoncés (CIDR, un par ligne)",
                allowed_subnet_peers_lbl: "ID de pairs de sous-réseau autorisés (* pour tous, un par ligne)",
                btn_cancel: "Annuler",
                btn_close: "Fermer",
                btn_test_save_peer: "➕ Tester et enregistrer un pair permanent",
                chosen_optimal: "🟢 Chemin optimal choisi",
                col_candidate_path: "Chemin candidat",
                col_exit_egress: "Trafic de sortie du nœud de sortie",
                col_inspector: "Inspecteur de décision",
                col_ip: "Adresse IP",
                col_rate: "Débit réel",
                col_ip_attr: "Nœud / Attribution",
                col_last_sync: "Dernière écoute",
                col_pkts: "Paquets",
                col_rationale: "Motif de décision / rejet",
                col_role: "Rôle du nœud",
                col_rtt_end: "RTT de bout en bout",
                col_rx_traffic: "Trafic de réception",
                col_status: "Statut",
                col_subnets: "Sous-réseaux annoncés",
                col_sync_channel: "Canal de découverte",
                col_tapmac: "MAC TAP",
                col_total_traffic: "Trafic total",
                col_tx_traffic: "Trafic d'émission",
                col_type: "Type",
                col_last_active: "Dernière activité",
                ip_scope_local: "TAP Local",
                ip_scope_peer: "Pair Mesh",
                ip_scope_subnet: "Sous-réseau LAN",
                ip_scope_exit: "Passerelle de Sortie",
                ip_scope_special: "Spécial L2",
                ip_scope_wan: "Internet WAN",
                btn_disconnecting: "Déconnexion...",
                topo_badge_peer: "Pair Mesh",
                via: "via",
                common_peer: "Pair",
                common_rtt: "RTT",
                common_unknown: "erreur inconnue",
                copied_toast: "📋 JSON de configuration copié dans le presse-papiers !",
                desc_arp: "Layer-2 Address Resolution",
                desc_broadcast: "Diffusion L2 (ARP incluse)",
                desc_gateway: "Tunnelisé via le nœud de sortie",
                desc_icmp: "Sondes réseau et keepalive",
                desc_multicast: "Multidiffusion L2 (mDNS incluse)",
                desc_seq_sync: "Pairs synchronisés · relecture / pertes de fenêtre",
                desc_tcp: "Flux d'octets fiables",
                desc_udp: "Transport de datagrammes",
                direct_optimal_desc: "La latence physique directe est plus rapide que toute route de relais multi-sauts candidate",
                direct_optimal_title: "P2P direct choisi (latence la plus faible)",
                disc_addrs: "Chemins d'adresses découverts",
                enable_acl_lbl: "Activer le moteur de pare-feu ACL",
                err_enter_multiaddr: "Veuillez saisir une chaîne Multiaddr valide",
                eval_table_title: "📊 Moteur de routage Dijkstra - chemins candidats évalués",
                exit_enable_desc: "Router le trafic Internet via ce pair",
                exit_nat_desc: "Traduction d'adresse source pour le trafic sortant",
                exit_node_desc: "Routage de sortie Internet via ce nœud",
                inspect_btn: "🔍 Inspecter",
                inspector_title: "🧭 Inspecteur de décision de routage intelligent",
                lbl_arp_broadcast: "ARP Broadcast Frames",
                lbl_broadcast_pkts: "Paquets de diffusion",
                lbl_gateway_pkts: "Paquets de passerelle du nœud de sortie",
                lbl_icmp_ping: "Écho ICMP (Ping)",
                lbl_multiaddr_str: "Chaîne Multiaddr",
                lbl_multicast_pkts: "Paquets de multidiffusion",
                lbl_seq_sync: "Sync de séquence et déduplication",
                lbl_tcp_packets: "Paquets de flux TCP",
                lbl_udp_packets: "Paquets de transport UDP",
                logs_cleared: "Journaux effacés.",
                modal_add_static_desc: "Saisissez une Multiaddr P2P complète contenant la cible /p2p/<PEER_ID>. L'adresse sera enregistrée de façon permanente dans le Peerstore avec PermanentAddrTTL et connectée automatiquement.",
                modal_add_static_title: "➕ Ajouter une Multiaddr de pair statique permanent",
                modal_diag_title: "⚡ Diagnostic de chemin de pair et benchmark",
                nat_fallback_desc: "contourne l'isolation NAT symétrique lorsque le lien P2P direct est inaccessible",
                no_arps: "Aucune entrée dans la table ARP",
                no_ips: "Aucun trafic par IP enregistré pour le moment",
                no_peer_metas: "Aucune métadonnée de pair reçue via peek-map / P2P",
                obfs_allow_switch_lbl: "Autoriser le changement de mode automatique",
                obfs_strict_key_lbl: "Négociation stricte des clés (PFS)",
                obfs_strict_key_desc: "Interdit le repli sur la clé de nœud de longue durée. Chaque paire de pairs doit dériver sa propre cipher à partir d'une clé ECDH éphémère à usage unique ; sinon ce pair reste en texte clair. Renforce l'isolation des clés par paire.",
                obfs_auto_title: "🤖 Détection automatique",
                obfs_block_size_desc: "Granularité d'alignement pour le mode bloc (octets)",
                obfs_block_size_lbl: "Taille d'alignement de bloc",
                obfs_dynamic_desc: "Plage min–max pour les trames de taille variable",
                obfs_dynamic_lbl: "Plage de taille dynamique (octets)",
                obfs_eval_interval_lbl: "Intervalle d'évaluation",
                obfs_jitter_desc: "Random jitter to break fixed-size patterns (0=off)",
                obfs_jitter_lbl: "Plage de gigue (±octets)",
                obfs_max_safe_desc: "PMTU safety threshold for obfuscated frames (bytes)",
                obfs_max_safe_lbl: "Max Safe Frame Size",
                obfs_threshold_lbl: "Seuil",
                packet_rate_title: "📊 Distribution du taux de paquets (Tx / Rx)",
                pcap_layer_frame: "Trame",
                pcap_layer_tree: "Analyse de protocole",
                peer_meta_title: "📡 Moniteur de métadonnées de pair et découverte Peek-Map",
                protocol_inspector_desc: "（Détail des paquets couche 2/3/4 et statistiques PPS en direct）",
                protocol_inspector_title: "📊 Inspecteur de trafic en direct et protocole Ethernet",
                proto_channels_title: "📡 Flux de Protocoles et Canaux Actifs",
                th_stream_proto: "Protocole / Canal",
                th_stream_peer: "Nœud Distant",
                th_stream_direction: "Direction",
                th_stream_transport: "Transport & Multiaddr",
                th_stream_status: "État",
                search_streams_ph: "Rechercher flux, protocoles, pairs…",
                no_matching_streams: "Aucun flux de protocole actif trouvé",
                no_channels: "Aucun canal de protocole actif",
                lbl_active_streams: "Flux",
                lbl_streams: "flux",
                dir_out: "Sortant ↑",
                dir_in: "Entrant ↓",
                stream_active: "Actif",
                channel_status_active: "Actif",
                channel_status_running: "En cours",
                channel_status_idle: "Inactif",
                channel_status_standby: "En attente",
                channel_status_ready: "Prêt",
                channel_status_open: "Mode ouvert",
                category_sync: "Synchronisation",
                category_routing: "Routage",
                category_pubsub: "PubSub",
                category_data: "Données",
                category_security: "Sécurité",
                category_transport: "Transport",
                category_diagnostics: "Diagnostics",
                category_discovery: "Découverte",
                channel_seqsync_name: "Synchronisation de séquence (SeqSync)",
                channel_seqsync_desc: "Déduplication de fenêtre & protection anti-rejeu",
                channel_lsa_name: "Routage maillé LSA",
                channel_lsa_desc: "Chemin le plus court Dijkstra",
                channel_peekmap_name: "Diffusion de topologie Peek-Map",
                channel_peekmap_desc: "Synchronisation topologique Bootstrap",
                channel_data_name: "Chemin de données TAP virtuel",
                channel_data_proto: "Superposition Ethernet couche 2",
                channel_auth_name: "Authentification de maillage PSK",
                channel_auth_desc: "Isolation réseau maillé PSK",
                channel_dcutr_name: "Poinçonnage NAT DCUtR & Relais",
                channel_dcutr_desc: "Mise à niveau vers connexion directe",
                cipher_lbl: "Chiffrement",

                rejected: "❌ Rejeté",
                relay_accel_active: "Accélération de relais active",
                relay_accel_desc: "Algorithme Dijkstra a calculé un chemin multi-sauts via",
                relay_chosen_title: "Relais intelligent choisi",
                reset_view: "🎯 Réinitialiser la vue",
                saved_latency: "économisé",
                section_acl_title: "🛡️ Éditeur de règles ACL maillé P2P style ZeroTier",
                section_acl_desc: "Règles de filtrage du trafic par pair",
                section_subnet_title: "🌐 Routeur de sous-réseau et autorisation",
                section_subnet_desc: "Annonce les sous-réseaux et autorise les pairs à les utiliser",
                target_node: "🎯 Nœud cible",
                toast_add_failed: "Échec de l'ajout du pair statique",
                toast_req_err: "Erreur de requête",
                toast_static_added: "Pair statique ajouté et enregistré de façon permanente dans le Peerstore !",
                toast_testing_adding: "Test et ajout du pair statique",
                topo_self_node: "Nœud propre",
                topo_standalone: "🌐 Nœud maillé autonome (en attente de connexions de pairs P2P...)",
                topology_sub: "（Glissez les nœuds pour repositionner | Molette pour zoomer | Double-clic pour Ping）",
                topology_title: "🗺️ Carte étoilée de topologie",
                unreachable: "Inaccessible",
                view_addr: "Voir Multiaddr",
                vs_direct: "par rapport au chemin direct",
                col_encryption: "Chiffrement",
                topo_legend_direct_fast: "● Direct (<30ms)",
                topo_legend_direct_slow: "● Direct (30-100ms)",
                topo_legend_relay: "● Relais de transit (ambre) — les pairs relayés pendent en dessous",
                topo_legend_flow: "💧 Densité de flux = débit TX/RX réel (les liens inactifs ne circulent pas)",
                topo_badge_transit: "🌉 Commutateur de transit",
                topo_badge_exit_server: "🚪 Serveur de sortie",
                topo_via: "via",
                topo_link_idle: "inactif",
                topo_summary_nodes: "Nœuds",
                topo_summary_direct: "Direct",
                topo_summary_relayed: "Relayés",
                topo_summary_relays: "Relais de transit",
                topo_summary_thru: "Débit maillé",
                topo_summary_gw: "Paquets passerelle",
                topo_summary_boots: "Bootstrap",
                topo_summary_static: "Pairs statiques",
                topo_summary_clusters: "Clusters",
                topo_filter_remote: "Inter-cluster",
                topo_legend_boot: "● Nœud bootstrap (violet)",
                topo_legend_overlay: "◆ Relais overlay (tiret long)",
                topo_badge_boot: "Bootstrap",
                topo_badge_static: "Statique",
                topo_tt_role_boot: "Nœud bootstrap",
                topo_tt_role_static: "Pair statique",
                topo_tt_cluster: "Cluster :",
                topo_tt_boot_hops: "Sauts boot :",
                topo_tt_transport_path: "Chemin de transport :",
                topo_tt_relay_hop: "Saut relais :",
                topo_tt_enc: "Chiffrement :",
                topo_tt_conn: "État de connexion :",
                topo_tt_jitter: "Jitter :",
                topo_tt_loss: "Perte :",
                topo_tt_version: "Version :",
                topo_tt_since: "Connecté :",
                topo_tt_geo: "Géo :",
                topo_tt_total: "Total (Tx/Rx) :",
                topo_tt_route_via: "Chemin :",
                topo_tt_blackhole: "Trou noir Rx (décalage dedup)",
                topo_tt_circuit_relay: "Relais de circuit v2",
                topo_tt_dedup_window: "Fenêtre dedup :",
                topo_tt_direct_link: "Lien P2P direct",
                topo_tt_dup_drops: "Paquets dupliqués ignorés :",
                topo_tt_healthy: "Sain",
                topo_tt_ipv4: "IPv4 virtuelle :",
                topo_tt_ipv6: "IPv6 virtuelle :",
                topo_tt_link_integrity: "Intégrité du lien :",
                topo_tt_live_rate: "Débit en direct :",
                topo_tt_local_host: "Hôte local",
                topo_tt_optimal_route: "Route optimale :",
                topo_tt_os_arch: "OS / Arch :",
                topo_tt_peer_id: "ID du pair :",
                topo_tt_route: "Route :",
                topo_tt_route_gain: "Gain de route :",
                topo_tt_rtt: "Latence RTT :",
                topo_tt_seq: "Séq (Tx/Rx) :",
                topo_tt_tap_ip: "IP du pair :",
                topo_tt_transit_relay: "Relais de transit",
                topo_tt_transport: "Transport :",
                topo_tt_uptime: "Temps de fonctionnement :"
            }
        };

        let currentLang = localStorage.getItem('p2ptap_lang') || (navigator.language && navigator.language.startsWith('zh') ? (navigator.language.includes('TW') || navigator.language.includes('HK') ? 'zh-TW' : 'zh-CN') : 'en');
        if (!i18nDict[currentLang]) currentLang = 'en';

        function t(key) {
            return (i18nDict[currentLang] && i18nDict[currentLang][key]) || (i18nDict.en[key] || key);
        }

        function setLanguage(lang) {
            if (!i18nDict[lang]) return;
            currentLang = lang;
            localStorage.setItem('p2ptap_lang', lang);
            document.getElementById('langSelect').value = lang;

            document.querySelectorAll('[data-i18n]').forEach(el => {
                const k = el.getAttribute('data-i18n');
                if (k) {
                    // Fall back to English for any key the active language lacks,
                    // so newly added labels (e.g. broadcast/multicast/gateway
                    // packets) always render instead of going blank.
                    el.innerText = t(k);
                }
            });

            document.querySelectorAll('[data-i18n-ph]').forEach(el => {
                const k = el.getAttribute('data-i18n-ph');
                if (k && i18nDict[lang][k]) {
                    el.placeholder = i18nDict[lang][k];
                }
            });

            document.getElementById('cfgPSK').placeholder = t('psk_placeholder');

            // pcap_desc contains HTML <span> tags, so use innerHTML instead of textContent
            const descEl = document.getElementById('pcapDescText');
            if (descEl) { descEl.innerHTML = t('pcap_desc'); }

            fetchStats();
        }

        let currentFullConfig = {};
        let lastTxBytes = 0;
        let lastRxBytes = 0;
        let lastFetchTime = Date.now();

        function formatBytes(bytes) {
            if (!bytes || bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function formatSpeed(bytesPerSec) {
            if (!bytesPerSec || bytesPerSec <= 0) return '⚡ 0 KB/s';
            if (bytesPerSec < 1024 * 1024) {
                return '⚡ ' + (bytesPerSec / 1024).toFixed(1) + ' KB/s';
            }
            return '⚡ ' + (bytesPerSec / (1024 * 1024)).toFixed(2) + ' MB/s';
        }

        // Compact rate formatter for tiny edge-label boxes (B / K / M / G).
        // Wider units (B/K/M/G) make the throughput legible at small fonts,
        // where the old "↑13.1 ↓5.8" lost both its arrows and its units.
        function formatRateCompact(bytesPerSec) {
            const b = Math.max(0, Number(bytesPerSec) || 0);
            if (b < 1024) return b.toFixed(0) + 'B';
            if (b < 1024 * 1024) return (b / 1024).toFixed(b < 10 * 1024 ? 2 : 1) + 'K';
            if (b < 1024 * 1024 * 1024) return (b / 1024 / 1024).toFixed(2) + 'M';
            return (b / 1024 / 1024 / 1024).toFixed(2) + 'G';
        }

        function onObfsModeChange() {
            const mode = document.getElementById('cfgObfsMode').value;
            const fieldMap = {
                'jitter': ['fixed', 'block', 'dynamic', 'random'],
                'fixed-size': ['fixed', 'random'],
                'dynamic-range': ['dynamic', 'auto'],
                'block-size': ['block'],
                'auto-fields': ['auto'],
            };
            document.querySelectorAll('[data-obfs-field]').forEach(el => {
                const field = el.getAttribute('data-obfs-field');
                const visible = fieldMap[field] ? fieldMap[field].includes(mode) : false;
                el.style.display = visible ? '' : 'none';
            });
        }

        function updateToggleLabel(chk, labelId, offText, onText) {
            const lbl = document.getElementById(labelId);
            if (lbl) lbl.textContent = chk.checked ? onText : offText;
        }

        function showToast(msg, isError, isWarn) {
            const tEl = document.getElementById('toast');
            tEl.innerText = msg;
            if (isWarn) {
                // Amber warning — used for "saved, but a restart is required".
                tEl.style.background = 'rgba(245, 158, 11, 0.92)';
                tEl.style.boxShadow = '0 10px 30px rgba(245, 158, 11, 0.4)';
            } else {
                tEl.style.background = isError ? 'rgba(239, 68, 68, 0.9)' : 'rgba(16, 185, 129, 0.9)';
                tEl.style.boxShadow = isError ? '0 10px 30px rgba(239, 68, 68, 0.4)' : '0 10px 30px rgba(16, 185, 129, 0.4)';
            }
            tEl.style.color = '#fff';
            tEl.classList.add('show');
            setTimeout(() => {
                tEl.classList.remove('show');
                // Reset to default after animation
                setTimeout(() => {
                    tEl.style.background = '';
                    tEl.style.boxShadow = '';
                }, 300);
            }, (isError || isWarn) ? 5000 : 3000);
        }

        async function openConfigModal() {
            try {
                const res = await fetch('/api/config', withAuth());
                if (!res.ok) return;
                currentFullConfig = await res.json();

                // Exit Node gateway relies on Linux nftables; hide the section on
                // other platforms since it cannot be enabled there.
                const isLinux = (currentFullConfig.platform || 'linux') === 'linux';
                const exitSection = document.getElementById('exitNodeConfigSection');
                if (exitSection) exitSection.style.display = isLinux ? '' : 'none';

                document.getElementById('cfgNodeName').value = currentFullConfig.node_name || '';
                document.getElementById('cfgStrategy').value = currentFullConfig.transport_strategy || 'best_path';
                document.getElementById('cfgPSK').value = currentFullConfig.psk || '';
                document.getElementById('cfgLogLevel').value = currentFullConfig.log_level || 'info';
                const transports = currentFullConfig.transports || {};
                const disableRelayEl = document.getElementById('cfgDisableRelay');
                if (disableRelayEl) {
                    disableRelayEl.checked = !!transports.disable_relay;
                    updateToggleLabel(disableRelayEl, 'cfgDisableRelayLabel', 'Off', 'On');
                }
                document.getElementById('cfgEnableMDNS').checked = !!currentFullConfig.enable_mdns;
                updateToggleLabel(document.getElementById('cfgEnableMDNS'), 'cfgEnableMDNSLabel', 'Off', 'On');

                const obfs = currentFullConfig.obfuscation || {};
                document.getElementById('cfgObfsMode').value = obfs.mode || 'random';
                document.getElementById('cfgFixedSize').value = obfs.fixed_size || 1500;
                document.getElementById('cfgFixedSizeBadge').textContent = obfs.fixed_size || 1500;
                document.getElementById('cfgJitterRange').value = obfs.jitter_range !== undefined ? obfs.jitter_range : 64;
                document.getElementById('cfgJitterRangeBadge').textContent = '±' + (obfs.jitter_range !== undefined ? obfs.jitter_range : 64);
                document.getElementById('cfgMinSize').value = obfs.min_size || 512;
                document.getElementById('cfgMaxSize').value = obfs.max_size || 1500;
                document.getElementById('cfgBlockSize').value = obfs.block_size || 256;
                document.getElementById('cfgAutoDetectInterval').value = obfs.auto_detect_interval || 30;
                document.getElementById('cfgAutoThresholdBytes').value = obfs.auto_threshold_bytes || 65536;
                document.getElementById('cfgAllowModeSwitch').checked = !!obfs.allow_mode_switch;
                updateToggleLabel(document.getElementById('cfgAllowModeSwitch'), 'cfgAllowModeSwitchLabel', 'Off', 'On');
                document.getElementById('cfgStrictKeyNegotiation').checked = !!obfs.strict_key_negotiation;
                updateToggleLabel(document.getElementById('cfgStrictKeyNegotiation'), 'cfgStrictKeyNegotiationLabel', 'Off', 'On');
                onObfsModeChange(); // show/hide mode-specific fields
                // Paint the filled portion of any range slider (Jitter, Fixed Size)
                // so the initial state isn't a blank track. updateRangeProgress is
                // itself no-op when min==max, so calling on every range is safe.
                document.querySelectorAll('#configModal input[type=range]').forEach(updateRangeProgress);
                CFG_LIST_DEFS.bootstrap.setState((currentFullConfig.bootstrap_peers || []).map(v => String(v)));
                renderCfgList('bootstrap');

                const exitNode = currentFullConfig.exit_node || {};
                document.getElementById('cfgExitEnable').checked = !!exitNode.enable;
                document.getElementById('cfgExitNAT').checked = exitNode.nat_masquerade !== false;
                document.getElementById('cfgExitWAN').value = exitNode.wan_interface || 'auto';

                CFG_LIST_DEFS.subnet.setState((currentFullConfig.advertised_subnets || []).map(v => String(v)));
                renderCfgList('subnet');
                document.getElementById('cfgAcceptSubnets').checked = !!currentFullConfig.accept_advertised_subnets;
                CFG_LIST_DEFS.peer.setState((currentFullConfig.allowed_subnet_peers || []).map(v => String(v)));
                renderCfgList('peer');

                const acl = currentFullConfig.acl || {};
                document.getElementById('cfgACLEnable').checked = !!acl.enable;
                document.getElementById('cfgACLDefaultAction').value = acl.default_action || 'accept';
                activeACLRules = acl.rules ? JSON.parse(JSON.stringify(acl.rules)) : [];
                // Refresh the rule list whenever the user toggles the
                // default policy so the list-mode hint banner and the
                // default-action flip on the "Add Rule" button stay in
                // sync with what the user just selected. Idempotent across
                // re-opens of the modal.
                const cfgDefSel = document.getElementById('cfgACLDefaultAction');
                if (cfgDefSel && !cfgDefSel.__aclLiveWired) {
                    cfgDefSel.__aclLiveWired = true;
                    cfgDefSel.addEventListener('change', () => {
                        try { renderACLRulesList(); } catch (e) { console.error(e); }
                    });
                }
                renderACLRulesList();

                // The `.modal-backdrop.active` CSS rule uses `display:flex !important`
                // so it stays shown even when other stylesheets override flex/grid.
                // We must add the `.active` class AND set inline display — style alone
                // is not enough (modal-backdrop.active's !important wins). Mirrors
                // openAddStaticPeerModal / login modal pattern.
                const cfgModal = document.getElementById('configModal');
                if (cfgModal) {
                    cfgModal.classList.add('active');
                    cfgModal.style.display = 'flex';
                }
            } catch (e) {
                console.error("Open config modal error:", e);
            }
        }

        function closeConfigModal() {
            const cfgModal = document.getElementById('configModal');
            if (cfgModal) {
                cfgModal.classList.remove('active');
                cfgModal.style.display = 'none';
            }
        }

        let activeACLRules = [];

        // ── Editable list state for the three textareas we replaced with
        //    ➕ Add / ✕ Delete rows: Bootstrap Peers, Advertised Subnets,
        //    Allowed Subnet Peer IDs. Each holds an array of string entries. ──
        let cfgListBootstrap = [];
        let cfgListSubnet    = [];
        let cfgListPeer      = [];

        // Accessor closures over the script-scoped `let` bindings. Done as
        // closures rather than the previous `window[def.state]` pattern
        // because `let` declarations at script top-level are NOT attached
        // to the `window` object — they're script-scoped only. Reading them
        // through `window.cfgListBootstrap` returned `undefined`, crashed
        // `state.length`, and was silently swallowed by `openConfigModal()`'s
        // try/catch — which is why the Settings button appeared to do
        // nothing. These getters/setters live in the same lexical scope as
        // the `let` bindings, so they see them directly.
        const CFG_LIST_DEFS = {
            bootstrap: {
                listId: 'cfgBootstrapList',
                placeholderKey: 'bootstrap_placeholder',
                getState: () => cfgListBootstrap,
                setState: (arr) => { cfgListBootstrap = arr; },
            },
            subnet: {
                listId: 'cfgAdvSubnetsList',
                placeholderKey: 'subnets_placeholder',
                getState: () => cfgListSubnet,
                setState: (arr) => { cfgListSubnet = arr; },
            },
            peer: {
                listId: 'cfgAllowedPeersList',
                placeholderKey: 'allowed_peers_placeholder',
                getState: () => cfgListPeer,
                setState: (arr) => { cfgListPeer = arr; },
            },
        };

        function renderCfgList(slug) {
            const def = CFG_LIST_DEFS[slug];
            if (!def) return;
            const list = document.getElementById(def.listId);
            if (!list) return;
            const rowsEl  = list.querySelector('.cfg-list-rows');
            const emptyEl = list.querySelector('.cfg-list-empty');
            const state   = def.getState();

            if (state.length === 0) {
                rowsEl.replaceChildren();
                if (emptyEl) {
                    emptyEl.textContent = t('cfg_list_empty');
                    emptyEl.hidden = false;
                }
                return;
            }
            if (emptyEl) emptyEl.hidden = true;

            rowsEl.replaceChildren();
            const frag = document.createDocumentFragment();
            state.forEach((value, idx) => {
                const row = document.createElement('div');
                row.className = 'cfg-list-row';
                row.setAttribute('draggable', 'true');
                row.setAttribute('data-idx', String(idx));

                const handle = document.createElement('span');
                handle.className = 'drag-handle';
                handle.title = t('drag_handle_tip');
                handle.setAttribute('aria-label', t('drag_handle_tip'));
                // Stop the row's drag handler from engaging when the user
                // grabs the handle, so accidental clicks on the handle do
                // not start a drag that interferes with the input focus.
                handle.addEventListener('mousedown', (e) => e.stopPropagation());
                const gripSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                gripSvg.setAttribute('aria-hidden', 'true');
                const gripUse = document.createElementNS('http://www.w3.org/2000/svg', 'use');
                gripUse.setAttribute('href', '#ic-grip');
                gripSvg.appendChild(gripUse);
                handle.appendChild(gripSvg);
                row.appendChild(handle);

                const input = document.createElement('input');
                input.type = 'text';
                input.className = 'cfg-list-input';
                input.placeholder = t(def.placeholderKey);
                input.value = (value == null ? '' : String(value));
                input.spellcheck = false;
                input.autocomplete = 'off';
                // Prevent the row from starting a drag when the user is
                // selecting text inside the input — the drag affordance
                // is the dedicated handle only.
                input.addEventListener('mousedown', (e) => e.stopPropagation());
                input.addEventListener('input', () => {
                    state[idx] = input.value;
                });
                row.appendChild(input);

                const delBtn = document.createElement('button');
                delBtn.type = 'button';
                delBtn.className = 'cfg-list-del btn-glass';
                delBtn.title = t('delete_rule');
                delBtn.setAttribute('aria-label', t('delete_rule'));
                delBtn.setAttribute('data-onclick',
                    `delCfgListItem('${slug}', ${idx})`);
                // Same drag-suppression pattern: clicking the delete button
                // must not start a drag.
                delBtn.addEventListener('mousedown', (e) => e.stopPropagation());
                const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                svg.classList.add('ico', 'btn-ico');
                svg.setAttribute('aria-hidden', 'true');
                const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
                use.setAttribute('href', '#ic-x');
                svg.appendChild(use);
                delBtn.appendChild(svg);
                row.appendChild(delBtn);

                frag.appendChild(row);
            });
            rowsEl.appendChild(frag);

            wireDragReorder(rowsEl, (from, to) => {
                moveCfgListItem(slug, from, to);
            });
        }

        // Generic HTML5 drag-and-drop reorder helper. Tracks the row under
        // the mouse via `data-idx` and reports the intended insertion
        // position (above or below) based on the cursor's mid-line. The
        // caller is responsible for mutating the underlying state array
        // and re-rendering.
        function wireDragReorder(container, onMove) {
            if (!container) return;
            let dragFrom = -1;

            container.addEventListener('dragstart', (e) => {
                const row = e.target.closest('[data-idx]');
                if (!row || !container.contains(row)) return;
                dragFrom = parseInt(row.getAttribute('data-idx'), 10);
                row.classList.add('is-dragging');
                if (e.dataTransfer) {
                    e.dataTransfer.effectAllowed = 'move';
                    // text/plain is required for Firefox; the value itself
                    // is unused because we re-read data-idx in `drop`.
                    e.dataTransfer.setData('text/plain', String(dragFrom));
                }
            });

            container.addEventListener('dragend', (e) => {
                const row = e.target.closest && e.target.closest('[data-idx]');
                if (row) row.classList.remove('is-dragging');
                container.querySelectorAll('.drop-above, .drop-below').forEach(el => {
                    el.classList.remove('drop-above', 'drop-below');
                });
                dragFrom = -1;
            });

            container.addEventListener('dragover', (e) => {
                if (dragFrom < 0) return;
                const row = e.target.closest && e.target.closest('[data-idx]');
                if (!row || !container.contains(row)) return;
                e.preventDefault();
                if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
                const rect = row.getBoundingClientRect();
                const above = (e.clientY - rect.top) < rect.height / 2;
                container.querySelectorAll('.drop-above, .drop-below').forEach(el => {
                    el.classList.remove('drop-above', 'drop-below');
                });
                row.classList.add(above ? 'drop-above' : 'drop-below');
            });

            container.addEventListener('dragleave', (e) => {
                const row = e.target.closest && e.target.closest('[data-idx]');
                if (!row) return;
                // Only clear when leaving the row entirely (not when
                // crossing into a child input/select).
                if (!row.contains(e.relatedTarget)) {
                    row.classList.remove('drop-above', 'drop-below');
                }
            });

            container.addEventListener('drop', (e) => {
                const row = e.target.closest && e.target.closest('[data-idx]');
                if (!row || !container.contains(row)) return;
                e.preventDefault();
                const rect = row.getBoundingClientRect();
                const above = (e.clientY - rect.top) < rect.height / 2;
                const to = parseInt(row.getAttribute('data-idx'), 10);
                const from = dragFrom;
                row.classList.remove('drop-above', 'drop-below');
                if (isNaN(from) || isNaN(to) || from < 0) return;
                // Convert "above row N" / "below row N" to the actual
                // insertion index in the post-splice array.
                let insertAt = above ? to : to + 1;
                if (from < insertAt) insertAt -= 1;
                if (insertAt === from) return;
                try { onMove(from, insertAt); } catch (err) { console.error('drag move error:', err); }
            });
        }

        function moveCfgListItem(slug, from, to) {
            const def = CFG_LIST_DEFS[slug];
            if (!def) return;
            const state = def.getState();
            if (from < 0 || from >= state.length) return;
            if (to < 0 || to >= state.length) return;
            if (from === to) return;
            const [m] = state.splice(from, 1);
            state.splice(to, 0, m);
            renderCfgList(slug);
        }

        function addCfgListItem(slug) {
            const def = CFG_LIST_DEFS[slug];
            if (!def) return;
            const state = def.getState();
            state.push('');
            renderCfgList(slug);
            // Focus the new row so the user can just start typing.
            const list = document.getElementById(def.listId);
            if (list) {
                const inputs = list.querySelectorAll('.cfg-list-input');
                const last = inputs[inputs.length - 1];
                if (last) {
                    last.focus();
                    try { last.setSelectionRange(last.value.length, last.value.length); } catch (_) {}
                }
            }
        }

        function delCfgListItem(slug, idx) {
            const def = CFG_LIST_DEFS[slug];
            if (!def) return;
            const state = def.getState();
            if (idx < 0 || idx >= state.length) return;
            state.splice(idx, 1);
            renderCfgList(slug);
        }

        function _aclActionAccept() { return { id: 'accept', label: t('acl_action_accept') }; }
        function _aclActionDrop()   { return { id: 'drop',   label: t('acl_action_drop')   }; }

        // `_buildACLSelect` accepts an optional `preferredFirst` option id.
        // When supplied, that option is moved to the top of the dropdown
        // without changing the selected value, so the menu always opens
        // with the semantically-expected choice in view. Used to swap the
        // rule-action menu order based on the default policy.
        function _buildACLSelect(value, options, cssClass, onChange, preferredFirst) {
            const sel = document.createElement('select');
            sel.className = 'form-select ' + cssClass;
            let ordered = options;
            if (preferredFirst != null) {
                const head = options.find(o => o.id === preferredFirst);
                const tail = options.filter(o => o.id !== preferredFirst);
                if (head) ordered = [head].concat(tail);
            }
            ordered.forEach(opt => {
                const o = document.createElement('option');
                o.value = opt.id;
                o.textContent = opt.label;
                if (opt.id === value) o.selected = true;
                sel.appendChild(o);
            });
            sel.addEventListener('mousedown', (e) => e.stopPropagation());
            sel.addEventListener('change', () => onChange(sel.value));
            return sel;
        }

        // Returns the action that is the *opposite* of the current default
        // policy. Rules in the list are exceptions to that policy, so the
        // natural new-rule default is its inverse:
        //   default_policy = drop   -> new rule defaults to 'accept'
        //   default_policy = accept -> new rule defaults to 'drop'
        // source is either 'cfgACLDefaultAction' (settings modal) or
        // 'aclEdDefault' (standalone editor modal).
        function _aclOppositeAction(source) {
            let def = 'accept';
            if (source === 'cfgACLDefaultAction') {
                const el = document.getElementById('cfgACLDefaultAction');
                if (el && el.value) def = el.value;
            } else if (source === 'aclEdDefault') {
                if (currentFullConfig && currentFullConfig.acl
                    && currentFullConfig.acl.default_action) {
                    def = currentFullConfig.acl.default_action;
                } else {
                    const el = document.getElementById('aclEdDefault');
                    if (el && el.value) def = el.value;
                }
            }
            def = String(def).toLowerCase();
            return (def === 'accept') ? 'drop' : 'accept';
        }

        function renderACLRulesList() {
            const listEl = document.getElementById('aclRulesList');
            if (!listEl) return;
            listEl.replaceChildren();

            // Derive the list "mode" from the default policy. Permit-mode
            // (default=DROP) means rules ALLOW exceptions; block-mode
            // (default=ACCEPT) means rules DENY exceptions. The hint banner
            // makes that semantics obvious so the user can never confuse
            // "rule says accept" with "this list always accepts".
            const defaultEl = document.getElementById('cfgACLDefaultAction');
            const defaultVal = (defaultEl && defaultEl.value
                ? String(defaultEl.value).toLowerCase() : 'accept');
            const isPermitMode = (defaultVal === 'drop');

            const hint = document.createElement('div');
            hint.className = 'acl-flow-hint ' + (isPermitMode ? 'mode-permit' : 'mode-block');
            const dot = document.createElement('span');
            dot.className = 'acl-flow-hint-dot';
            hint.appendChild(dot);
            const hintText = document.createElement('span');
            hintText.textContent = isPermitMode
                ? t('acl_flow_hint_permit')
                : t('acl_flow_hint_block');
            hint.appendChild(hintText);
            listEl.appendChild(hint);

            if (activeACLRules.length === 0) {
                const empty = document.createElement('div');
                empty.className = 'cfg-list-empty';
                empty.textContent = t('acl_no_rules_short');
                listEl.appendChild(empty);
                return;
            }

            const frag = document.createDocumentFragment();
            activeACLRules.forEach((r, idx) => {
                const row = document.createElement('div');
                const actionId = (r.action === 'drop' || r.action === 'deny') ? 'drop' : 'accept';
                row.className = 'acl-rule-row action-' + actionId;
                row.setAttribute('draggable', 'true');
                row.setAttribute('data-idx', String(idx));

                const head = document.createElement('div');
                head.className = 'acl-rule-head';

                const handle = document.createElement('span');
                handle.className = 'drag-handle';
                handle.title = t('drag_rule_tip');
                handle.setAttribute('aria-label', t('drag_rule_tip'));
                handle.addEventListener('mousedown', (e) => e.stopPropagation());
                const gripSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                gripSvg.setAttribute('aria-hidden', 'true');
                const gripUse = document.createElementNS('http://www.w3.org/2000/svg', 'use');
                gripUse.setAttribute('href', '#ic-grip');
                gripSvg.appendChild(gripUse);
                handle.appendChild(gripSvg);
                head.appendChild(handle);

                const num = document.createElement('span');
                num.className = 'acl-rule-num';
                num.textContent = '#' + (idx + 1);
                head.appendChild(num);

                // Action chip (theme-aware) + hidden select that drives it.
                const actionChip = document.createElement('span');
                actionChip.className = 'acl-rule-action' + (actionId === 'drop' ? ' action-drop' : '');
                actionChip.textContent = (actionId === 'drop') ? t('acl_action_drop') : t('acl_action_accept');
                head.appendChild(actionChip);

                const actionSel = _buildACLSelect(
                    actionId,
                    [_aclActionAccept(), _aclActionDrop()],
                    'action-select',
                    (v) => updateACLRuleItem(idx, 'action', v),
                    // Promote the natural-exception action to the top of
                    // the dropdown so the user sees the semantically
                    // expected choice first.
                    isPermitMode ? 'accept' : 'drop'
                );
                head.appendChild(actionSel);

                const dirSel = _buildACLSelect(
                    (!r.direction || r.direction === 'both') ? 'both'
                      : (r.direction === 'inbound' ? 'in' : 'out'),
                    [{ id: 'both',    label: t('acl_dir_both') },
                     { id: 'in',      label: t('acl_dir_in') },
                     { id: 'out',     label: t('acl_dir_out') }],
                    'dir-select',
                    (v) => updateACLRuleItem(idx, 'direction', v === 'in' ? 'inbound' : (v === 'out' ? 'outbound' : 'both'))
                );
                head.appendChild(dirSel);

                const protoSel = _buildACLSelect(
                    (!r.protocol || r.protocol === 'any') ? 'any' : r.protocol,
                    [{ id: 'any',  label: t('acl_proto_any') },
                     { id: 'tcp',  label: t('acl_proto_tcp') },
                     { id: 'udp',  label: t('acl_proto_udp') },
                     { id: 'icmp', label: t('acl_proto_icmp') }],
                    'proto-select',
                    (v) => updateACLRuleItem(idx, 'protocol', v)
                );
                head.appendChild(protoSel);

                const delBtn = document.createElement('button');
                delBtn.type = 'button';
                delBtn.className = 'acl-rule-del';
                delBtn.title = t('delete_rule');
                delBtn.setAttribute('aria-label', t('delete_rule'));
                delBtn.setAttribute('data-onclick', `deleteACLRuleRow(${idx})`);
                delBtn.addEventListener('mousedown', (e) => e.stopPropagation());
                const delSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                delSvg.setAttribute('aria-hidden', 'true');
                const delUse = document.createElementNS('http://www.w3.org/2000/svg', 'use');
                delUse.setAttribute('href', '#ic-trash');
                delSvg.appendChild(delUse);
                delBtn.appendChild(delSvg);
                head.appendChild(delBtn);

                row.appendChild(head);

                const fields = document.createElement('div');
                fields.className = 'acl-rule-fields';
                const peerInput = document.createElement('input');
                peerInput.type = 'text';
                peerInput.className = 'form-input';
                peerInput.placeholder = t('acl_peer_placeholder');
                peerInput.value = r.peer_id || '*';
                peerInput.addEventListener('mousedown', (e) => e.stopPropagation());
                peerInput.addEventListener('change', () => updateACLRuleItem(idx, 'peer_id', peerInput.value));
                const cidrInput = document.createElement('input');
                cidrInput.type = 'text';
                cidrInput.className = 'form-input';
                cidrInput.placeholder = t('acl_cidr_placeholder');
                cidrInput.value = r.ip_cidr || '*';
                cidrInput.addEventListener('mousedown', (e) => e.stopPropagation());
                cidrInput.addEventListener('change', () => updateACLRuleItem(idx, 'ip_cidr', cidrInput.value));
                const portInput = document.createElement('input');
                portInput.type = 'text';
                portInput.className = 'form-input';
                portInput.placeholder = t('acl_port_placeholder');
                portInput.value = r.port || '0';
                portInput.addEventListener('mousedown', (e) => e.stopPropagation());
                portInput.addEventListener('change', () => updateACLRuleItem(idx, 'port', portInput.value));
                fields.appendChild(peerInput);
                fields.appendChild(cidrInput);
                fields.appendChild(portInput);
                row.appendChild(fields);

                const comment = document.createElement('input');
                comment.type = 'text';
                comment.className = 'form-input';
                comment.placeholder = t('acl_comment_placeholder');
                comment.value = r.comment || '';
                comment.addEventListener('mousedown', (e) => e.stopPropagation());
                comment.addEventListener('change', () => updateACLRuleItem(idx, 'comment', comment.value));
                const commentWrap = document.createElement('div');
                commentWrap.className = 'acl-rule-comment';
                commentWrap.appendChild(comment);
                row.appendChild(commentWrap);

                frag.appendChild(row);
            });
            listEl.appendChild(frag);

            wireDragReorder(listEl, (from, to) => moveACLRuleItem(from, to));
        }

        function moveACLRuleItem(from, to) {
            if (from < 0 || from >= activeACLRules.length) return;
            if (to < 0 || to >= activeACLRules.length) return;
            if (from === to) return;
            const [m] = activeACLRules.splice(from, 1);
            activeACLRules.splice(to, 0, m);
            renderACLRulesList();
        }

        function addACLRuleRow() {
            activeACLRules.push({
                rule_id: 'rule-' + Date.now(),
                // Default to the action OPPOSITE the configured default
                // policy: if "Default Deny" is set, exceptions are permit
                // rules; if "Default Allow" is set, exceptions are block
                // rules. Matches the user's mental model of "what kind of
                // exceptions am I adding?".
                action: _aclOppositeAction('cfgACLDefaultAction'),
                direction: 'both',
                peer_id: '*',
                ip_cidr: '*',
                protocol: 'any',
                port: '0',
                comment: ''
            });
            renderACLRulesList();
        }

        function deleteACLRuleRow(idx) {
            activeACLRules.splice(idx, 1);
            renderACLRulesList();
        }

        function updateACLRuleItem(idx, key, val) {
            if (activeACLRules[idx]) {
                activeACLRules[idx][key] = val;
                // Live-re-render so the action chip + left-bar tint track the
                // new value without a full save round-trip.
                if (key === 'action') renderACLRulesList();
            }
        }

        // ---- Standalone ACL Editor Modal (rich, drag-to-reorder) ----
        function openACLEditor() {
            try {
                if (!currentFullConfig.acl) currentFullConfig.acl = { enable: false, default_action: 'accept', rules: [] };
                if (!Array.isArray(currentFullConfig.acl.rules)) currentFullConfig.acl.rules = [];
                document.getElementById('aclEdEnable').checked = !!currentFullConfig.acl.enable;
                document.getElementById('aclEdDefault').value = currentFullConfig.acl.default_action || 'accept';
                // Live-refresh the editor rule list when the user flips its
                // default policy, so the list-mode hint banner + the action
                // dropdown ordering track the selection. The onChange is
                // wired once to avoid duplicate fires on repeated re-opens.
                const edDefSel = document.getElementById('aclEdDefault');
                if (edDefSel && !edDefSel.__aclLiveWired) {
                    edDefSel.__aclLiveWired = true;
                    edDefSel.addEventListener('change', () => {
                        try {
                            currentFullConfig.acl.default_action = edDefSel.value;
                            renderEditorACLRules();
                        } catch (err) { console.error(err); }
                    });
                }
                renderEditorACLRules();
                document.getElementById('aclEditorModal').style.display = 'flex';
            } catch (e) {
                console.error('openACLEditor error:', e);
            }
        }

        function closeACLEditor() {
            const m = document.getElementById('aclEditorModal');
            if (m) m.style.display = 'none';
        }

        function renderEditorACLRules() {
            const listEl = document.getElementById('aclEditorRulesList');
            if (!listEl) return;
            const rules = currentFullConfig.acl.rules;
            listEl.replaceChildren();

            // List "mode" — driven by the editor's default-action select
            // value (already synced into currentFullConfig when the user
            // touches the select). Permit-mode = drop default, rules
            // accept exceptions; block-mode = accept default, rules deny
            // exceptions.
            const defaultVal = String(
                currentFullConfig.acl.default_action || 'accept').toLowerCase();
            const isPermitMode = (defaultVal === 'drop');

            const hint = document.createElement('div');
            hint.className = 'acl-flow-hint ' + (isPermitMode ? 'mode-permit' : 'mode-block');
            const hintDot = document.createElement('span');
            hintDot.className = 'acl-flow-hint-dot';
            hint.appendChild(hintDot);
            const hintText = document.createElement('span');
            hintText.textContent = isPermitMode
                ? t('acl_flow_hint_permit')
                : t('acl_flow_hint_block');
            hint.appendChild(hintText);
            listEl.appendChild(hint);

            if (rules.length === 0) {
                const empty = document.createElement('div');
                empty.className = 'cfg-list-empty';
                empty.style.textAlign = 'center';
                empty.style.padding = '14px';
                empty.textContent = t('acl_no_rules');
                listEl.appendChild(empty);
                return;
            }

            const frag = document.createDocumentFragment();
            rules.forEach((r, idx) => {
                const row = document.createElement('div');
                const actionId = (r.action === 'drop' || r.action === 'deny') ? 'drop' : 'accept';
                row.className = 'acl-rule-row action-' + actionId;
                row.setAttribute('draggable', 'true');
                row.setAttribute('data-idx', String(idx));

                const head = document.createElement('div');
                head.className = 'acl-rule-head';

                const handle = document.createElement('span');
                handle.className = 'drag-handle';
                handle.title = t('drag_rule_tip');
                handle.setAttribute('aria-label', t('drag_rule_tip'));
                handle.addEventListener('mousedown', (e) => e.stopPropagation());
                const gripSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                gripSvg.setAttribute('aria-hidden', 'true');
                const gripUse = document.createElementNS('http://www.w3.org/2000/svg', 'use');
                gripUse.setAttribute('href', '#ic-grip');
                gripSvg.appendChild(gripUse);
                handle.appendChild(gripSvg);
                head.appendChild(handle);

                const num = document.createElement('span');
                num.className = 'acl-rule-num';
                num.textContent = '#' + (idx + 1);
                head.appendChild(num);

                const actionChip = document.createElement('span');
                actionChip.className = 'acl-rule-action' + (actionId === 'drop' ? ' action-drop' : '');
                actionChip.textContent = (actionId === 'drop') ? t('acl_action_drop') : t('acl_action_accept');
                head.appendChild(actionChip);

                const actionSel = _buildACLSelect(
                    actionId,
                    [_aclActionAccept(), _aclActionDrop()],
                    'action-select',
                    (v) => updateEditorACLRuleItem(idx, 'action', v),
                    isPermitMode ? 'accept' : 'drop'
                );
                head.appendChild(actionSel);

                const dirSel = _buildACLSelect(
                    (!r.direction || r.direction === 'both') ? 'both'
                      : (r.direction === 'inbound' ? 'in' : 'out'),
                    [{ id: 'both',    label: t('acl_dir_both') },
                     { id: 'in',      label: t('acl_dir_in') },
                     { id: 'out',     label: t('acl_dir_out') }],
                    'dir-select',
                    (v) => updateEditorACLRuleItem(idx, 'direction', v === 'in' ? 'inbound' : (v === 'out' ? 'outbound' : 'both'))
                );
                head.appendChild(dirSel);

                const protoSel = _buildACLSelect(
                    (!r.protocol || r.protocol === 'any') ? 'any' : r.protocol,
                    [{ id: 'any',  label: t('acl_proto_any') },
                     { id: 'tcp',  label: t('acl_proto_tcp') },
                     { id: 'udp',  label: t('acl_proto_udp') },
                     { id: 'icmp', label: t('acl_proto_icmp') }],
                    'proto-select',
                    (v) => updateEditorACLRuleItem(idx, 'protocol', v)
                );
                head.appendChild(protoSel);

                // Editor modal keeps the explicit ▲ / ▼ move buttons alongside
                // drag-to-reorder — same `moveEditorACLRule(idx, dir)` helper,
                // just rendered as themed icon buttons.
                const upBtn = document.createElement('button');
                upBtn.type = 'button';
                upBtn.className = 'acl-rule-del';
                upBtn.title = t('move_up_tip');
                upBtn.setAttribute('aria-label', t('move_up_tip'));
                upBtn.setAttribute('data-onclick', `moveEditorACLRule(${idx}, -1)`);
                upBtn.addEventListener('mousedown', (e) => e.stopPropagation());
                const upSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                upSvg.setAttribute('aria-hidden', 'true');
                const upUse = document.createElementNS('http://www.w3.org/2000/svg', 'use');
                upUse.setAttribute('href', '#ic-arrow-up');
                upSvg.appendChild(upUse);
                upBtn.appendChild(upSvg);
                head.appendChild(upBtn);

                const downBtn = document.createElement('button');
                downBtn.type = 'button';
                downBtn.className = 'acl-rule-del';
                downBtn.title = t('move_down_tip');
                downBtn.setAttribute('aria-label', t('move_down_tip'));
                downBtn.setAttribute('data-onclick', `moveEditorACLRule(${idx}, 1)`);
                downBtn.addEventListener('mousedown', (e) => e.stopPropagation());
                const downSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                downSvg.setAttribute('aria-hidden', 'true');
                const downUse = document.createElementNS('http://www.w3.org/2000/svg', 'use');
                downUse.setAttribute('href', '#ic-arrow-down');
                downSvg.appendChild(downUse);
                downBtn.appendChild(downSvg);
                head.appendChild(downBtn);

                const delBtn = document.createElement('button');
                delBtn.type = 'button';
                delBtn.className = 'acl-rule-del';
                delBtn.title = t('delete_rule');
                delBtn.setAttribute('aria-label', t('delete_rule'));
                delBtn.setAttribute('data-onclick', `deleteEditorACLRule(${idx})`);
                delBtn.addEventListener('mousedown', (e) => e.stopPropagation());
                const delSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                delSvg.setAttribute('aria-hidden', 'true');
                const delUse = document.createElementNS('http://www.w3.org/2000/svg', 'use');
                delUse.setAttribute('href', '#ic-trash');
                delSvg.appendChild(delUse);
                delBtn.appendChild(delSvg);
                head.appendChild(delBtn);

                row.appendChild(head);

                const fields = document.createElement('div');
                fields.className = 'acl-rule-fields';
                const peerInput = document.createElement('input');
                peerInput.type = 'text';
                peerInput.className = 'form-input';
                peerInput.placeholder = t('acl_peer_placeholder');
                peerInput.value = r.peer_id || '*';
                peerInput.addEventListener('mousedown', (e) => e.stopPropagation());
                peerInput.addEventListener('change', () => updateEditorACLRuleItem(idx, 'peer_id', peerInput.value));
                const cidrInput = document.createElement('input');
                cidrInput.type = 'text';
                cidrInput.className = 'form-input';
                cidrInput.placeholder = t('acl_cidr_placeholder');
                cidrInput.value = r.ip_cidr || '*';
                cidrInput.addEventListener('mousedown', (e) => e.stopPropagation());
                cidrInput.addEventListener('change', () => updateEditorACLRuleItem(idx, 'ip_cidr', cidrInput.value));
                const portInput = document.createElement('input');
                portInput.type = 'text';
                portInput.className = 'form-input';
                portInput.placeholder = t('acl_port_placeholder');
                portInput.value = r.port || '0';
                portInput.addEventListener('mousedown', (e) => e.stopPropagation());
                portInput.addEventListener('change', () => updateEditorACLRuleItem(idx, 'port', portInput.value));
                fields.appendChild(peerInput);
                fields.appendChild(cidrInput);
                fields.appendChild(portInput);
                row.appendChild(fields);

                const comment = document.createElement('input');
                comment.type = 'text';
                comment.className = 'form-input';
                comment.placeholder = t('acl_comment_placeholder');
                comment.value = r.comment || '';
                comment.addEventListener('mousedown', (e) => e.stopPropagation());
                comment.addEventListener('change', () => updateEditorACLRuleItem(idx, 'comment', comment.value));
                const commentWrap = document.createElement('div');
                commentWrap.className = 'acl-rule-comment';
                commentWrap.appendChild(comment);
                row.appendChild(commentWrap);

                frag.appendChild(row);
            });
            listEl.appendChild(frag);

            wireDragReorder(listEl, (from, to) => {
                const arr = currentFullConfig.acl.rules;
                if (from < 0 || from >= arr.length) return;
                if (to < 0 || to >= arr.length) return;
                if (from === to) return;
                const [m] = arr.splice(from, 1);
                arr.splice(to, 0, m);
                renderEditorACLRules();
            });
        }

        function addEditorACLRule() {
            const tmpl = document.getElementById('aclEdTemplate');
            const kind = tmpl ? tmpl.value : '';
            if (kind) {
                applyACLTemplate(kind);
                if (tmpl) tmpl.value = '';
            } else {
                currentFullConfig.acl.rules.push({
                    rule_id: 'rule-' + Date.now(),
                    // Same exception-of-default policy: new rules start as
                    // the opposite of the editor's configured default
                    // action so the rule list always feels coherent.
                    action: _aclOppositeAction('aclEdDefault'),
                    direction: 'both', peer_id: '*',
                    ip_cidr: '*', protocol: 'any', port: '0', comment: ''
                });
            }
            renderEditorACLRules();
        }

        function deleteEditorACLRule(idx) {
            currentFullConfig.acl.rules.splice(idx, 1);
            renderEditorACLRules();
        }

        function updateEditorACLRuleItem(idx, key, val) {
            const r = currentFullConfig.acl.rules[idx];
            if (r) r[key] = val;
        }

        function moveEditorACLRule(idx, dir) {
            const arr = currentFullConfig.acl.rules;
            const to = idx + dir;
            if (to < 0 || to >= arr.length) return;
            const [m] = arr.splice(idx, 1);
            arr.splice(to, 0, m);
            renderEditorACLRules();
        }

        function applyACLTemplate(kind) {
            const map = {
                ssh:     { action: 'accept', direction: 'both', peer_id: '*', ip_cidr: '*', protocol: 'tcp', port: '22', comment: 'Allow SSH' },
                web:     { action: 'accept', direction: 'both', peer_id: '*', ip_cidr: '*', protocol: 'tcp', port: '443', comment: 'Allow Web (HTTPS)' },
                dns:     { action: 'drop',   direction: 'both', peer_id: '*', ip_cidr: '*', protocol: 'udp', port: '53', comment: 'Block DNS' },
                rdp:     { action: 'accept', direction: 'both', peer_id: '*', ip_cidr: '*', protocol: 'tcp', port: '3389', comment: 'Allow RDP' },
                denyall: { action: 'drop',   direction: 'both', peer_id: '*', ip_cidr: '*', protocol: 'any', port: '0', comment: 'Deny all remaining' }
            };
            const base = map[kind];
            if (!base) return;
            currentFullConfig.acl.rules.push(Object.assign({ rule_id: 'rule-' + Date.now() }, base));
        }

        async function saveACLEditor() {
            try {
                currentFullConfig.acl.enable = document.getElementById('aclEdEnable').checked;
                currentFullConfig.acl.default_action = document.getElementById('aclEdDefault').value;
                const res = await fetch('/api/config', withAuth({
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(currentFullConfig)
                }));
                if (res.ok) {
                    showToast(t('save_success'));
                    closeACLEditor();
                    fetchStats();
                } else {
                    const err = await res.json().catch(() => ({}));
                    alert(t('save_failed') + (err.error || 'Unknown Error'));
                }
            } catch (e) {
                console.error('saveACLEditor error:', e);
                alert(t('req_error') + e.message);
            }
        }

        // ---- ACL Rule Tester Modal (mirrors node.MatchACL) ----
        function openACLTestModal() {
            const m = document.getElementById('aclTestModal');
            if (m) m.style.display = 'flex';
            const res = document.getElementById('aclTestResult');
            if (res) res.innerHTML = '';
        }

        function closeACLTest() {
            const m = document.getElementById('aclTestModal');
            if (m) m.style.display = 'none';
        }

        function _aclCidrContains(cidr, ip) {
            try {
                const parts = cidr.split('/');
                const base = parts[0];
                const maskBits = parseInt(parts[1], 10);
                const ipParts = ip.split('.').map(Number);
                const baseParts = base.split('.').map(Number);
                if (ipParts.length !== 4 || baseParts.length !== 4) return false;
                const mask = maskBits === 0 ? 0 : (0xFFFFFFFF << (32 - maskBits)) >>> 0;
                const ipInt = ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0;
                const baseInt = ((baseParts[0] << 24) | (baseParts[1] << 16) | (baseParts[2] << 8) | baseParts[3]) >>> 0;
                return (ipInt & mask) === (baseInt & mask);
            } catch (e) { return false; }
        }

        function simulateACLMatch(acl, pkt) {
            if (!acl || !acl.enable) return { allowed: true, rule: null, note: 'engine-disabled' };
            for (const rule of acl.rules) {
                const dir = (rule.direction || '').toLowerCase();
                if (dir === 'inbound' && pkt.is_tx) continue;
                if (dir === 'outbound' && !pkt.is_tx) continue;
                const pid = rule.peer_id || '';
                if (pid && pid !== '*' && pid !== pkt.peer_id) continue;
                const proto = (rule.protocol || '').toLowerCase();
                if (proto && proto !== 'any' && proto !== pkt.protocol) continue;
                if (rule.port && rule.port !== '0' && pkt.dst_port > 0) {
                    if (rule.port.indexOf('-') >= 0) {
                        const pp = rule.port.split('-');
                        if (pp.length === 2) {
                            const minP = parseInt(pp[0], 10);
                            const maxP = parseInt(pp[1], 10);
                            if (pkt.dst_port < minP || pkt.dst_port > maxP) continue;
                        }
                    } else {
                        const pVal = parseInt(rule.port, 10);
                        if (pVal > 0 && pkt.dst_port !== pVal) continue;
                    }
                }
                if (rule.ip_cidr && rule.ip_cidr !== '*' && pkt.dst_ip) {
                    if (!_aclCidrContains(rule.ip_cidr, pkt.dst_ip)) continue;
                }
                const act = (rule.action || '').toLowerCase();
                return { allowed: (act === 'accept' || act === 'allow'), rule: rule, note: 'matched' };
            }
            const def = (acl.default_action || 'accept').toLowerCase();
            return { allowed: (def === 'accept' || def === 'allow' || def === ''), rule: null, note: 'default' };
        }

        function runACLTest() {
            try {
                const peer = document.getElementById('aclTestPeer').value.trim() || '*';
                const dir = document.getElementById('aclTestDir').value;
                const proto = document.getElementById('aclTestProto').value;
                const dstIP = document.getElementById('aclTestDstIP').value.trim();
                const portRaw = document.getElementById('aclTestDstPort').value.trim();
                const dstPort = portRaw === '' ? 0 : (parseInt(portRaw, 10) || 0);
                const pkt = { peer_id: peer, is_tx: (dir === 'outbound'), protocol: proto, dst_ip: dstIP, dst_port: dstPort };
                const acl = currentFullConfig.acl || { enable: false, default_action: 'accept', rules: [] };
                const result = simulateACLMatch(acl, pkt);
                const allow = result.allowed;
                const rule = result.rule;
                let html = '';
                html += `<div style="display:flex; align-items:center; gap:10px; padding:12px 14px; border-radius:10px; background:${allow ? 'var(--accent-green-fill)' : 'var(--danger-fill)'}; border:1px solid ${allow ? 'var(--accent-green-border)' : 'var(--danger-border)'}; margin-bottom:10px;">`;
                html += `<span style="font-size:1.4rem;">${allow ? '✅' : '⛔'}</span>`;
                html += `<div><div style="font-weight:700; font-size:1rem; color:${allow ? 'var(--success)' : 'var(--danger)'};">${allow ? t('acl_test_allow') : t('acl_test_deny')}</div>`;
                html += `<div style="font-size:0.78rem; color:var(--text-secondary);">${proto.toUpperCase()} → ${dstIP || 'any'}:${dstPort || 'any'} (${dir})</div></div></div>`;
                if (rule) {
                    const idx = acl.rules.indexOf(rule) + 1;
                    html += `<div style="font-size:0.82rem; color:var(--text-dim); margin-bottom:6px;">${t('acl_test_matched')} <b style="color:var(--accent-purple);">#${idx}</b>${rule.comment ? ' — ' + rule.comment : ''}</div>`;
                    html += `<div style="font-size:0.75rem; color:var(--text-muted);">${rule.action.toUpperCase()} · ${rule.direction} · ${rule.protocol} · ${rule.ip_cidr || '*'} : ${rule.port || '0'}</div>`;
                } else {
                    html += `<div style="font-size:0.82rem; color:var(--text-dim);">${t('acl_test_default')} (${acl.default_action || 'accept'})</div>`;
                }
                document.getElementById('aclTestResult').innerHTML = html;
            } catch (e) {
                console.error('runACLTest error:', e);
            }
        }

        async function saveConfigModal() {
            try {
                // Snapshot the pre-save relay setting so we can tell the user
                // when a change needs a restart to actually take effect.
                const prevDisableRelay = !!(currentFullConfig.transports && currentFullConfig.transports.disable_relay);

                currentFullConfig.node_name = document.getElementById('cfgNodeName').value;
                currentFullConfig.transport_strategy = document.getElementById('cfgStrategy').value;
                currentFullConfig.psk = document.getElementById('cfgPSK').value;
                currentFullConfig.log_level = document.getElementById('cfgLogLevel').value;
                currentFullConfig.enable_mdns = document.getElementById('cfgEnableMDNS').checked;

                if (!currentFullConfig.transports) currentFullConfig.transports = {};
                const disableRelayEl = document.getElementById('cfgDisableRelay');
                if (disableRelayEl) currentFullConfig.transports.disable_relay = disableRelayEl.checked;

                if (!currentFullConfig.obfuscation) currentFullConfig.obfuscation = {};
                const ob = currentFullConfig.obfuscation;
                ob.mode = document.getElementById('cfgObfsMode').value;
                ob.fixed_size = parseInt(document.getElementById('cfgFixedSize').value, 10) || 1500;
                ob.block_size = parseInt(document.getElementById('cfgBlockSize').value, 10) || 256;
                ob.jitter_range = parseInt(document.getElementById('cfgJitterRange').value, 10) || 0;
                ob.min_size = parseInt(document.getElementById('cfgMinSize').value, 10) || 512;
                ob.max_size = parseInt(document.getElementById('cfgMaxSize').value, 10) || 1500;
                ob.auto_detect_interval = parseInt(document.getElementById('cfgAutoDetectInterval').value, 10) || 30;
                ob.auto_threshold_bytes = parseInt(document.getElementById('cfgAutoThresholdBytes').value, 10) || 65536;
                ob.allow_mode_switch = document.getElementById('cfgAllowModeSwitch').checked;
                ob.strict_key_negotiation = document.getElementById('cfgStrictKeyNegotiation').checked;

                currentFullConfig.bootstrap_peers = cfgListBootstrap.map(s => (s == null ? '' : String(s)).trim()).filter(s => s.length > 0);

                const isLinux = (currentFullConfig.platform || 'linux') === 'linux';
                if (isLinux) {
                    if (!currentFullConfig.exit_node) currentFullConfig.exit_node = {};
                    currentFullConfig.exit_node.enable = document.getElementById('cfgExitEnable').checked;
                    currentFullConfig.exit_node.nat_masquerade = document.getElementById('cfgExitNAT').checked;
                    currentFullConfig.exit_node.wan_interface = document.getElementById('cfgExitWAN').value || 'auto';
                }

                currentFullConfig.advertised_subnets = cfgListSubnet.map(s => (s == null ? '' : String(s)).trim()).filter(s => s.length > 0);
                currentFullConfig.accept_advertised_subnets = document.getElementById('cfgAcceptSubnets').checked;
                currentFullConfig.allowed_subnet_peers = cfgListPeer.map(s => (s == null ? '' : String(s)).trim()).filter(s => s.length > 0);

                if (!currentFullConfig.acl) currentFullConfig.acl = {};
                currentFullConfig.acl.enable = document.getElementById('cfgACLEnable').checked;
                currentFullConfig.acl.default_action = document.getElementById('cfgACLDefaultAction').value;
                currentFullConfig.acl.rules = activeACLRules;

                const res = await fetch('/api/config', withAuth({
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(currentFullConfig)
                }));

                if (res.ok) {
                    // `disable_relay` only persists to disk and is read at
                    // startup — the running node won't re-evaluate it until a
                    // restart (same as the rest of the `transports` block).
                    const newDisableRelay = !!(currentFullConfig.transports && currentFullConfig.transports.disable_relay);
                    if (prevDisableRelay !== newDisableRelay) {
                        const hint = t('cfg_needs_restart') || 'Disable-relay changed — restart p2ptap to apply.';
                        showToast(t('save_success') + ' ' + hint, false, true);
                    } else {
                        showToast(t('save_success'));
                    }
                    closeConfigModal();
                    fetchStats();
                } else {
                    const err = await res.json();
                    alert(t('save_failed') + (err.error || 'Unknown Error'));
                }
            } catch (e) {
                console.error("Save config error:", e);
                alert(t('req_error') + e.message);
            }
        }

        async function togglePeerAsExitGateway(peerID, tapIP, tapIPv6) {
            // The control card's buttons have no per-peer id, so the button
            // lookup is purely cosmetic (loading/active state). Never bail out
            // when it's absent — otherwise Connect/Disconnect clicks do nothing.
            const btn = document.getElementById('exitGwBtn_' + peerID);
            if (btn && btn.classList.contains('loading')) return; // ignore double-clicks

            const isCurrent = !!btn && btn.classList.contains('active');
            const action = isCurrent ? 'clear' : 'set';
            const originalHTML = btn ? btn.innerHTML : '';

            if (btn) {
                btn.classList.add('loading');
                const gwIcon = btn.querySelector('.gw-icon');
                const gwLabel = btn.querySelector('.gw-label-text');
                if (gwIcon) gwIcon.style.display = 'none';
                if (gwLabel) gwLabel.textContent = isCurrent ? 'Disconnecting...' : 'Connecting...';
            }

            try {
                const res = await fetch('/api/exitnode', withAuth({
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    // Dual-stack: send both families so the backend installs the
                    // IPv4 AND IPv6 split-default routes when the peer advertises
                    // a v6 TAP IP. A blank v6 value keeps legacy IPv4-only peers
                    // behaving exactly as before.
                    body: JSON.stringify({ action: action, peer_id: peerID, exit_tap_ip: tapIP || '', exit_tap_ipv6: tapIPv6 || '' })
                }));
                if (res.ok) {
                    // Success — will refresh UI via fetchStats
                    showToast(isCurrent
                        ? (t('exit_disconnected') || 'Exit Gateway disconnected')
                        : (t('exit_connected') || 'Exit Gateway connected to ') + (tapIP || peerID));
                    // Give backend a moment to apply routing before refresh
                    setTimeout(() => fetchStats(), 800);
                } else {
                    const err = await res.json().catch(() => ({}));
                    showToast('❌ ' + (err.error || 'Operation failed'), true);
                    // Restore button on error
                    if (btn) { btn.classList.remove('loading', 'active'); btn.innerHTML = originalHTML; }
                }
            } catch (e) {
                console.error('Toggle exit gateway error:', e);
                showToast('❌ Network error: ' + e.message, true);
                if (btn) { btn.classList.remove('loading', 'active'); btn.innerHTML = originalHTML; }
            }
        }

        let currentMultiaddrPeerID = null;

        function openMultiaddrModal(peerID) {
            const peer = (cachedPeers || []).find(p => p.peer_id === peerID);
            if (!peer) return;
            currentMultiaddrPeerID = peerID;

            const allAddrsList = (peer.all_addrs && peer.all_addrs.length > 0) ? peer.all_addrs : [peer.addr];
            document.getElementById('multiaddrModalTitle').textContent =
                '🛣️ ' + allAddrsList.length + ' ' + (t('disc_addrs') || 'Discovered Multiaddr Pathways');

            // Resolve the "current active connection pathway" header text.
            // This header reports only the LIVE libp2p connection (sourced
            // from PeerInfoDTO.Addr); a separate "best reachable" line is
            // added below when probe results are cached and no live conn exists.
            const liveActive = (peer.addr && peer.addr !== 'unknown')
                ? escapeHTML(peer.addr)
                : null;

            // Look up a recent cached probe for this peer. The 5-minute TTL
            // ensures the "best reachable" line is not stale (a reachable
            // address now may be unreachable later). Only show this second
            // header line when there is no live libp2p connection — otherwise
            // the user already sees the active multiaddr on line 1 and a
            // secondary candidate list would be redundant noise.
            let bestReachableHtml = '';
            if (!liveActive) {
                const cached = multiaddrProbeCache.get(peerID);
                if (cached && (Date.now() - cached.ts) < MULTIADDR_PROBE_TTL_MS) {
                    // Same inconclusive-tolerant sort as the live probe render path:
                    // candidates with rtt_ms <= 0 are pushed to the end so the
                    // "best reachable" line only ever points at a real measurement.
                    const cmp = (a, b) => {
                        const av = (typeof a.rtt_ms === 'number' && a.rtt_ms > 0) ? a.rtt_ms : Number.POSITIVE_INFINITY;
                        const bv = (typeof b.rtt_ms === 'number' && b.rtt_ms > 0) ? b.rtt_ms : Number.POSITIVE_INFINITY;
                        return av - bv;
                    };
                    const candidates = cached.results
                        .filter(r => r.reachable && !r.is_active && r.rtt_ms > 0)
                        .slice()
                        .sort(cmp);
                    if (candidates.length > 0) {
                        const best = candidates[0];
                        const suffix = ` (${best.rtt_ms} ms)`;
                        const label = t('best_reachable_pathway') || 'Best reachable candidate (from last multiaddr probe)';
                        bestReachableHtml = `
                            <div style="margin-top:4px; font-size:0.78rem; color:var(--text-secondary);">
                                <span style="font-weight:600; color:var(--success);">✅ ${label}:</span>
                                <code style="font-size:0.72rem; word-break:break-all;">${escapeHTML(best.addr)}${suffix}</code>
                            </div>`;
                    }
                }
            }

            const activeHeaderHtml = liveActive
                ? `<span style="font-weight:600; color:var(--accent-cyan);">⚡ ${liveActive}</span>
                   <span style="margin-left:6px;">${t('active_pathway') || 'Current Active Connected Pathway'}</span>`
                : `<span style="font-weight:600; color:var(--text-muted);">⚡ ${escapeHTML(peer.addr)}</span>
                   <span style="margin-left:6px; color:var(--text-muted);">${t('active_pathway_unknown') || 'No Live Connection'}</span>`;

            const body = document.getElementById('multiaddrModalBody');
            body.innerHTML = `
                <div style="font-size:0.78rem; color:var(--text-secondary); margin-bottom:8px;">
                    ${activeHeaderHtml}
                    ${bestReachableHtml}
                </div>
                <div id="maModalResults" style="display:flex; flex-direction:column; gap:4px; max-height:320px; overflow-y:auto; padding-right:2px;">
                    ${allAddrsList.map((a, idx) => {
                        const isActive = (a === peer.addr);
                        const tag = isActive ? '🟢 Active' : '⚪ Candidate';
                        return `<div class="ma-entry${isActive ? ' active' : ''}" data-ma-index="${idx}" data-ma-addr="${escapeHTML(a)}">
                            <span class="ma-tag">[${tag}]</span>
                            <span class="ma-addr-text">${a}</span>
                            <span class="ma-rtt" style="display:none; margin-left:6px; font-size:0.68rem; font-weight:bold;"></span>
                        </div>`;
                    }).join('')}
                </div>
            `;

            const m = document.getElementById('multiaddrModal');
            m.classList.add('active');
        }

        function closeMultiaddrModal() {
            const m = document.getElementById('multiaddrModal');
            m.classList.remove('active');
            currentMultiaddrPeerID = null;
        }

        async function testPeerMultiaddrs(peerID, popoverPeerID) {
            // Operates on the click-to-open multiaddr modal.
            const resultsDiv = document.getElementById('maModalResults');
            const btn = document.getElementById('multiaddrModalProbeBtn');
            if (!resultsDiv) return;
            if (btn && btn.disabled) return;

            // Disable button during probing
            if (btn) {
                btn.disabled = true;
                btn.classList.add('probing');
                btn.textContent = t('probing_text');
            }

            // Reset all entries to pending state
            const entries = resultsDiv.querySelectorAll('.ma-entry');
            entries.forEach(entry => {
                const rttSpan = entry.querySelector('.ma-rtt');
                if (rttSpan) {
                    rttSpan.style.display = 'inline-block';
                    rttSpan.textContent = '...';
                    rttSpan.style.color = '#94a3b8';
                    rttSpan.style.background = 'rgba(148, 163, 184, 0.12)';
                    rttSpan.style.padding = '1px 5px';
                    rttSpan.style.borderRadius = '3px';
                }
            });

            try {
                const res = await fetch('/api/multiaddr-test', withAuth({
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ peer_id: peerID })
                }));

                if (!res.ok) {
                    const err = await res.json().catch(() => ({ error: 'HTTP ' + res.status }));
                    showToast('🧪 Multiaddr test failed: ' + (err.error || 'Unknown error'), true);
                    return;
                }

                const data = await res.json();
                const results = data.results || [];

                // Persist the fresh probe results so opening the popup again
                // (or reopening it after closing) keeps the "Best Reachable"
                // header line consistent without re-probing.
                if (peerID && results.length > 0) {
                    multiaddrProbeCache.set(peerID, { results: results, ts: Date.now() });
                }

                // Identify the "Best Reachable" entry — the lowest-RTT reachable
                // non-active row — so we can promote its tag from "Reachable"
                // to "Best" and reflect it in the popup header line.
                const liveActiveAddr = (() => {
                    const p = (cachedPeers || []).find(pp => pp.peer_id === peerID);
                    return (p && p.addr && p.addr !== 'unknown') ? p.addr : '';
                })();
                const bestAddr = (() => {
                    // Compare rtt_ms ascending but push "inconclusive" probes
                    // (rtt_ms <= 0, the -1 sentinel from the backend) to the end
                    // so a Best-promotion decision is only made between candidates
                    // that actually have a measured RTT.
                    const cmp = (a, b) => {
                        const av = (typeof a.rtt_ms === 'number' && a.rtt_ms > 0) ? a.rtt_ms : Number.POSITIVE_INFINITY;
                        const bv = (typeof b.rtt_ms === 'number' && b.rtt_ms > 0) ? b.rtt_ms : Number.POSITIVE_INFINITY;
                        return av - bv;
                    };
                    const cands = (results || [])
                        .filter(r => r.reachable && !r.is_active && r.addr !== liveActiveAddr && r.rtt_ms > 0)
                        .slice()
                        .sort(cmp);
                    return cands.length > 0 ? cands[0].addr : null;
                })();

                // Update each entry with real results
                results.forEach((r, idx) => {
                    const entry = resultsDiv.querySelector('.ma-entry[data-ma-index="' + idx + '"]');
                    if (!entry) return;

                    const tagSpan = entry.querySelector('.ma-tag');
                    const rttSpan = entry.querySelector('.ma-rtt');
                    if (!rttSpan) return;

                    let rttClass, rttText, tagIcon;
                    if (r.note) {
                        // Relay/circuit path: per-path RTT is inconclusive; the backend
                        // carries the cached EWMA in `note` as an *estimate*. Reuse the
                        // existing purple relay style and mark it estimated (the "*").
                        rttClass = 'ma-rtt-relay';
                        const estMatch = /≈\s*(\d+)\s*ms/.exec(r.note);
                        rttText = estMatch ? `≈${estMatch[1]}ms*` : 'est*';
                        tagIcon = '🔗 Relay';
                    } else if (r.error && r.error.includes('relay')) {
                        rttClass = 'ma-rtt-relay';
                        rttText = 'relay';
                        tagIcon = '🔗 Relay';
                    } else if (r.reachable) {
                        if (typeof r.rtt_ms !== 'number' || r.rtt_ms <= 0) {
                            // Backend sentinel: dial succeeded in <1ms but no real
                            // handshake was verified (typical for raw UDP "connect"
                            // on a routable IP, or /p2p-circuit without EWMA).
                            // Render as "unverified / —" rather than "Reachable · 0 ms"
                            // so the operator doesn't trust a non-existent latency.
                            rttClass = 'ma-rtt-inconclusive';
                            rttText = t('probe_unverified') || 'unverified';
                        } else if (r.rtt_ms < 30) {
                            rttClass = 'ma-rtt-fast';
                        } else if (r.rtt_ms < 100) {
                            rttClass = 'ma-rtt-mid';
                        } else {
                            rttClass = 'ma-rtt-slow';
                        }
                        if (typeof r.rtt_ms === 'number' && r.rtt_ms > 0) {
                            rttText = r.rtt_ms + 'ms';
                        }
                        // Promote the lowest-RTT non-active reachable to "Best"
                        // so the popup has an obvious "this is the candidate I
                        // would dial next" marker when no live conn exists.
                        // Only candidates with a real measured RTT are eligible
                        // (bestAddr filter above already excludes inconclusive).
                        if (r.is_active) {
                            tagIcon = '🟢 Active';
                        } else if (bestAddr && r.addr === bestAddr) {
                            tagIcon = '★ Best';
                        } else if (typeof r.rtt_ms !== 'number' || r.rtt_ms <= 0) {
                            tagIcon = '⚪ Unverified';
                        } else {
                            tagIcon = r.rtt_ms < 100 ? '🟡 Reachable' : '🟠 Slow';
                        }
                    } else {
                        rttClass = 'ma-rtt-fail';
                        rttText = 'unreachable';
                        tagIcon = '🔴 Timeout';
                    }

                    // Update tag
                    if (tagSpan) tagSpan.textContent = '[' + tagIcon + ']';

                    // Update RTT badge
                    rttSpan.style.display = 'inline';
                    rttSpan.className = 'ma-rtt-badge ' + rttClass;
                    rttSpan.textContent = rttText;

                    // Update entry border color to reflect status.
                    // "Best" gets a slightly stronger emphasis than "Reachable".
                    if (r.reachable) {
                        entry.style.borderColor = (bestAddr && r.addr === bestAddr && !r.is_active)
                            ? 'rgba(251, 191, 36, 0.6)'
                            : 'rgba(52, 211, 153, 0.4)';
                    } else if (!r.error || !r.error.includes('relay')) {
                        entry.style.borderColor = 'rgba(248, 113, 113, 0.4)';
                    }
                });

                // Count reachable vs unreachable
                const reachableCount = results.filter(r => r.reachable).length;
                const totalCount = results.length;
                showToast(t('probe_result').replace('{reachable}', reachableCount).replace('{total}', totalCount));

            } catch (e) {
                console.error('Multiaddr test error:', e);
                showToast(t('probe_error') + ': ' + e.message, true);
            } finally {
                // Re-enable button
                if (btn) {
                    btn.disabled = false;
                    btn.classList.remove('probing');
                    btn.textContent = t('test_all');
                }
            }
        }

        function setPingTarget(target) {
            document.getElementById('pingTargetInput').value = target;
        }

        function sanitizePingTarget(input) {
            // Accept CIDR-suffixed TAP IPs as well as bare addresses.
            return input
                .trim()
                .replace(/^ping\s+/i, '')
                .replace(/^traceroute\s+/i, '')
                .replace(/^tracert\s+/i, '')
                .replace(/^curl\s+/i, '')
                .replace(/^nslookup\s+/i, '')
                .replace(/^dig\s+/i, '')
                .trim();
        }

        // stripCIDR removes an optional "/N" suffix from a TAP-IP-style input.
        // Both the server's ActivePeers row and the user's input field use this
        // normalisation before equality matching, so "10.0.0.2" can find a row
        // whose stored tap_ip is "10.0.0.2/24".
        function stripCIDR(s) {
            if (!s) return '';
            const idx = s.indexOf('/');
            return idx >= 0 ? s.slice(0, idx) : s;
        }

        // resolveTargetToPeer applies the same layered lookup the backend uses
        // (peer_id / tap_ip / tap_ipv6 / node_name / AllAddrs / node_name
        // substring) so the cached peer list and the server agree. Returns
        // {matchedPeer | null, queryID, matchedKey}.
        function resolveTargetToPeer(target) {
            const normTarget = stripCIDR(target || '');
            const lower = normTarget.toLowerCase();
            let matchedPeer = null;
            let matchedKey = '';

            if (Array.isArray(cachedPeers)) {
                matchedPeer = cachedPeers.find(p => {
                    if (p.peer_id === target) { matchedKey = 'peer_id'; return true; }
                    if (p.tap_ip && stripCIDR(p.tap_ip) === normTarget) { matchedKey = 'tap_ip'; return true; }
                    if (p.tap_ipv6 && stripCIDR(p.tap_ipv6) === normTarget) { matchedKey = 'tap_ipv6'; return true; }
                    if (p.node_name && p.node_name.toLowerCase() === lower) { matchedKey = 'node_name'; return true; }
                    if (p.node_name && lower && p.node_name.toLowerCase().includes(lower)) {
                        matchedKey = 'node_name_substring';
                        return true;
                    }
                    if (Array.isArray(p.all_addrs) && normTarget) {
                        const hit = p.all_addrs.some(a => {
                            const s = String(a);
                            return s.includes('/ip4/' + normTarget + '/') ||
                                   s.includes('/ip6/' + normTarget + '/') ||
                                   s.endsWith('/ip4/' + normTarget) ||
                                   s.endsWith('/ip6/' + normTarget);
                        });
                        if (hit) matchedKey = 'all_addrs';
                        return hit;
                    }
                    return false;
                });
            }

            return {
                matchedPeer,
                queryID: (matchedPeer && matchedPeer.peer_id) ? matchedPeer.peer_id : normTarget,
                matchedKey,
            };
        }

        // renderKnownPeersHint turns a backend-supplied known_peers list into a
        // clickable suggestion block when the API refused the input.
        function renderKnownPeersHint(knownPeers) {
            if (!Array.isArray(knownPeers) || knownPeers.length === 0) return '';
            const items = knownPeers.map(name => `  • ${name}`).join('\n');
            return `Known peers currently in the LSA-fed ActivePeers set:\n${items}`;
        }

        function runPingDiagnostics() {
            const rawTarget = document.getElementById('pingTargetInput').value.trim() || '10.0.0.2';
            const target = sanitizePingTarget(rawTarget) || '10.0.0.2';
            const out = document.getElementById('pingOutput');
            const lines = [
                `P2P Ping → ${target}`,
                `[libp2p ping stream — real RTT, not ICMP]`,
                `Pinging...`,
            ];
            out.innerText = lines.join('\n');

            // Resolve a real peer_id if the user typed a TAP IP / node name.
            const resolved = resolveTargetToPeer(target);
            const matchedPeer = resolved.matchedPeer;
            const queryID = resolved.queryID;
            if (resolved.matchedKey) {
                lines.push(`Resolved via ${resolved.matchedKey}: ${queryID.slice(0, 12)}...`);
            }

            safeFetchJSON(`/api/ping?peer_id=${encodeURIComponent(queryID)}`)
                .then(result => {
                    if (!result.ok) {
                        lines.push('', result.error || 'ping failed');
                        const d = result.data || {};
                        if (d && d.hint) lines.push(`Hint: ${d.hint}`);
                        const known = renderKnownPeersHint(d.known_peers);
                        if (known) lines.push('', known);
                        showPingFallback(lines, target, matchedPeer);
                        out.innerText = lines.join('\n');
                        return;
                    }
                    const d = result.data;
                    const t = (x) => (x != null ? x.toFixed(1) : '-');
                    const transport = d.is_relayed ? '🔄 Circuit Relay (中转)' : '⚡ Direct P2P (直连)';
                    lines.push('');
                    lines.push(`Peer: ${d.node_name || d.peer_id_short}  (${d.peer_id_short})`);
                    if (d.tap_ip) lines.push(`  TAP: ${d.tap_ip}`);
                    lines.push(`Transport: ${transport}  [${d.transport_path}]`);
                    lines.push(`Probes: ${d.probes}   Loss: ${(d.packet_loss * 100).toFixed(0)}%`);
                    lines.push(`RTT  min/avg/max: ${t(d.rtt_min_ms)} / ${t(d.rtt_avg_ms)} / ${t(d.rtt_max_ms)} ms`);
                    lines.push(`Jitter: ${t(d.jitter_ms)} ms`);
                    if (d.is_relayed && d.relay_path && d.relay_path.length) {
                        lines.push(`Relay path (${d.relay_path.length} hop): ` + d.relay_path.map(r => '…' + r.slice(-9)).join(' → '));
                    }
                    if (d.transport_addr) lines.push(`Transport addr: ${d.transport_addr}`);
                    if (d.error) lines.push(`Note: ${d.error}`);
                    if (!d.success) lines.push('', `Peer ${target} did not reply. Check connectivity.`);
                    out.innerText = lines.join('\n');
                })
                .catch(err => {
                    lines.push('', `Ping error: ${err.message || err}`);
                    showPingFallback(lines, target, matchedPeer);
                    out.innerText = lines.join('\n');
                });
        }

        function showPingFallback(lines, target, matchedPeer) {
            let baseRTT = 0;
            if (matchedPeer) { baseRTT = matchedPeer.rtt_ms || 0; }
            if (baseRTT <= 0) { baseRTT = 80; }

            const rtts = [Math.round(baseRTT*0.92), Math.round(baseRTT), Math.round(baseRTT*1.04), Math.round(baseRTT*0.96)];
            lines.push(`Fallback estimate (based on cached routing RTT ≈${baseRTT} ms):`);
            rtts.forEach((r, i) => {
                lines.push(`  64 bytes: icmp_seq=${i+1} rtt≈${r} ms [estimated]`);
            });
            const avg = (rtts.reduce((a,b)=>a+b,0)/4).toFixed(1);
            lines.push('', `--- ESTIMATED ---`, `4 probes, rtt avg≈${avg} ms`);
            lines.push(`WARNING: This is an estimation, not real ICMP! Run 'ping ${target}' in terminal.`);
        }

        function runTracerouteDiagnostics() {
            const rawTarget = document.getElementById('pingTargetInput').value.trim() || '10.0.0.2';
            const target = sanitizePingTarget(rawTarget) || '10.0.0.2';
            const out = document.getElementById('pingOutput');
            const lines = [
                `P2P Overlay Traceroute → ${target}`,
                `[libp2p has no native traceroute; traces LSA/Dijkstra forwarding path + per-leg transport]`,
                `Tracing overlay path...`,
            ];
            out.innerText = lines.join('\n');

            // Resolve a real peer_id if the user typed a TAP IP / node name.
            const resolved = resolveTargetToPeer(target);
            const matchedPeer = resolved.matchedPeer;
            const queryID = resolved.queryID;
            if (resolved.matchedKey) {
                lines.push(`Resolved via ${resolved.matchedKey}: ${queryID.slice(0, 12)}...`);
            }

            safeFetchJSON(`/api/traceroute?peer_id=${encodeURIComponent(queryID)}`)
                .then(tr => {
                    if (!tr.ok) {
                        lines.push('', tr.error || 'No overlay route found');
                        const d = tr.data || {};
                        if (d && d.hint) lines.push(`Hint: ${d.hint}`);
                        const known = renderKnownPeersHint(d.known_peers);
                        if (known) lines.push('', known);
                        renderCachedTraceroute(lines, target, queryID);
                        out.innerText = lines.join('\n');
                        return;
                    }
                    const d = tr.data;
                    const relayCount = (d.hops || []).filter(h => h.role === 'relay').length;
                    lines.push('');
                    lines.push(`Path (${d.hop_count} node, ${relayCount} relay): ${d.is_direct ? 'Direct' : d.transport_path}   [source: ${d.source}]`);
                    (d.hops || []).forEach((h, i) => {
                        const badge = h.role === 'local' ? '⟡ LOCAL' : (h.role === 'destination' ? '▶ DEST' : '↺ RELAY');
                        const exit = h.is_exit_node ? ' 🚀EXIT' : '';
                        const ip = h.tap_ip ? ` (${h.tap_ip})` : '';
                        const short = h.peer_id_short || h.peer_id;
                        let line = `  ${i + 1}  ${badge}  ${h.node_name || short}${ip}${exit}`;
                        if (h.link_class) {
                            const leg = h.link_class === 'circuit-relay' ? '🔄 circuit' : '⚡ direct';
                            line += `\n      ↳ ${leg}  leg RTT ~${h.link_rtt_ms} ms  cum ~${h.cumulative_rtt_ms} ms`;
                            if (h.transport_addr) line += `\n      ↳ ${h.transport_addr}`;
                        }
                        lines.push(line);
                    });
                    if (d.total_rtt_ms > 0) lines.push('', `Path RTT (sum of overlay edges): ~${d.total_rtt_ms} ms`);
                    if (!d.is_direct && d.saved_rtt_ms > 0) lines.push(`  [relay saved ${d.saved_rtt_ms} ms vs direct ${d.direct_rtt_ms} ms]`);
                    lines.push('', `---`, `For real ICMP traceroute: traceroute ${target}`);
                    out.innerText = lines.join('\n');
                })
                .catch(err => {
                    lines.push('', `API error: ${err.message || err}`);
                    renderCachedTraceroute(lines, target, queryID);
                    out.innerText = lines.join('\n');
                });
        }

        function renderCachedTraceroute(lines, target, queryID) {
            const matchedRoute = cachedRoutes.find(r =>
                r.dest_peer === queryID || r.tap_ip === target ||
                (r.dest_name && r.dest_name.toLowerCase() === target.toLowerCase())
            );
            if (matchedRoute && matchedRoute.path_names && matchedRoute.path_names.length > 0) {
                const relays = matchedRoute.path_names.length - 1;
                lines.push(`Cached path (${relays} hop):`);
                matchedRoute.path_names.forEach((hn, idx) => {
                    const role = idx === 0 ? '⟡ LOCAL' : (idx === matchedRoute.path_names.length - 1 ? '▶ DEST' : '↺ RELAY');
                    lines.push(`  ${idx + 1}  ${role}  ${hn}`);
                });
                lines.push(`Route RTT: ~${matchedRoute.total_rtt_ms} ms [estimated]`);
            } else {
                lines.push(`No cached route and no live overlay route available for ${target}.`);
            }
            lines.push('', `---`, `For real ICMP traceroute: traceroute ${target}`, `If ICMP fails, check TAP: /api/tap/info`);
        }

        function inspectRoute(destPeer) {
            const r = cachedRoutes.find(route => route.dest_peer === destPeer);
            if (!r) return;

            const modal = document.getElementById('routeInspectorModal');
            const content = document.getElementById('inspectorContent');

            let decisionBadge = '';
            let decisionText = '';
            if (r.is_direct) {
                decisionBadge = `<span class="pill-badge role-static" style="font-size:0.85rem; padding:4px 12px;">🟢 ${t('direct_optimal_title')}</span>`;
                decisionText = `<strong>${t('direct_optimal_title')}:</strong> ${t('direct_optimal_desc')} (<strong>${r.direct_rtt_ms} ms</strong>).`;
            } else {
                decisionBadge = `<span class="pill-badge role-bootstrap" style="font-size:0.85rem; padding:4px 12px;">🔀 ${t('relay_chosen_title')} (${r.next_hop_name})</span>`;
                const savedStr = r.saved_rtt_ms > 0 ? `${t('saved_latency')} <strong style="color:var(--success);">${r.saved_rtt_ms} ms</strong> (${t('vs_direct')} <strong>${r.direct_rtt_ms} ms</strong>)` : `${t('nat_fallback_desc')}`;
                decisionText = `<strong>${t('relay_accel_active')}:</strong> ${t('relay_accel_desc')} <strong>${r.next_hop_name}</strong> (${r.total_rtt_ms} ms), ${savedStr}.`;
            }

            let candidateRows = '';
            const candidates = r.candidates || [];
            if (candidates.length > 0) {
                candidateRows = candidates.map(c => {
                    const optTag = c.is_optimal 
                        ? `<span style="color:var(--success); font-weight:bold;">${t('chosen_optimal')}</span>` 
                        : `<span style="color:var(--text-secondary);">${t('rejected')}</span>`;
                    const rttStr = c.total_rtt > 0 ? `${c.total_rtt} ms` : `<span style="color:var(--danger);">∞ (${t('unreachable')})</span>`;
                    const pathStr = c.path_names.join(' ➔ ');
                    return `
                        <tr>
                            <td>${optTag}</td>
                            <td><code style="color:var(--accent-purple);">${pathStr}</code></td>
                            <td><strong>${rttStr}</strong></td>
                            <td style="color:var(--text-dim); font-size:0.82rem;">${c.reason}</td>
                        </tr>
                    `;
                }).join('');
            }

            content.innerHTML = `
                <div class="glass-card" style="padding:14px; background:var(--surface-fill);">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                        <strong style="color:var(--text-primary); font-size:1.02rem;">${t('target_node')}: ${r.dest_name}</strong>
                        <code>IP: ${escapeHTML(r.tap_ip)}</code>
                    </div>
                    <div style="margin-bottom:8px;">${decisionBadge}</div>
                    <div style="color:var(--text-dim); line-height:1.5;">${decisionText}</div>
                </div>

                <div style="margin-top:6px;">
                    <strong style="color:var(--text-primary); font-size:0.92rem; display:block; margin-bottom:8px;">${t('eval_table_title')}</strong>
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>${t('col_status')}</th>
                                    <th>${t('col_candidate_path')}</th>
                                    <th>${t('col_rtt_end')}</th>
                                    <th>${t('col_rationale')}</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${candidateRows}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;

            modal.style.display = 'flex';
        }

        function closeRouteInspector() {
            document.getElementById('routeInspectorModal').style.display = 'none';
        }

        // ==========================================
        // P2P Connectivity Troubleshooter
        // ==========================================

        function populateTroubleshooterDropdown() {
            const select = document.getElementById('troubleshootPeerSelect');
            if (!select) return;

            const currentVal = select.value;
            const hasFocus = document.activeElement === select;
            
            let html = `<option value="" disabled selected>${t('troubleshoot_select_peer') || 'Select a Peer to Diagnose'}</option>`;
            cachedPeers.forEach(p => {
                const name = p.node_name || 'Unknown Node';
                const v4 = p.tap_ip ? `v4: ${escapeHTML(p.tap_ip)}` : '';
                const v6 = p.tap_ipv6 ? `v6: ${escapeHTML(p.tap_ipv6)}` : '';
                const ipStr = [v4, v6].filter(Boolean).join(' | ') || 'No IP';
                html += `<option value="${escapeHTML(p.peer_id)}">${escapeHTML(name)} (${ipStr})</option>`;
            });
            
            if (select.innerHTML !== html && !hasFocus) {
                select.innerHTML = html;
                if (currentVal && cachedPeers.some(p => p.peer_id === currentVal)) {
                    select.value = currentVal;
                }
            }
        }

        // --- WebUI auth token handling (mirrors server-side bearer requirement) ---
        const AUTH_TOKEN_KEY = 'p2ptap_webui_token';
        function getAuthToken() {
            try { return localStorage.getItem(AUTH_TOKEN_KEY) || ''; } catch (e) { return ''; }
        }
        function setAuthToken(tok) {
            try { localStorage.setItem(AUTH_TOKEN_KEY, tok); } catch (e) {}
        }
        // Inject the bearer token into a fetch options object without clobbering
        // any caller-supplied headers.
        function withAuth(options) {
            options = options || {};
            const tok = getAuthToken();
            if (tok) {
                options.headers = Object.assign({}, options.headers, { 'Authorization': 'Bearer ' + tok });
            }
            if (!options.headers) options.headers = {};
            return options;
        }
        // Promise-based in-page login modal (replaces native window.prompt).
        let loginModalActive = false;
        let loginResolve = null;

        function openLoginModal() {
            return new Promise((resolve) => {
                if (loginModalActive) { loginResolve = resolve; return; }
                loginModalActive = true;
                loginResolve = resolve;
                const modal = document.getElementById('loginModal');
                const input = document.getElementById('loginTokenInput');
                const err = document.getElementById('loginError');
                err.style.display = 'none';
                err.textContent = '';
                input.value = getAuthToken() || '';
                modal.style.display = 'flex';
                setTimeout(() => input.focus(), 50);
            });
        }

        function closeLoginModal(success) {
            const modal = document.getElementById('loginModal');
            modal.style.display = 'none';
            loginModalActive = false;
            const r = loginResolve;
            loginResolve = null;
            if (r) r(success);
        }

        function submitLogin() {
            const input = document.getElementById('loginTokenInput');
            const err = document.getElementById('loginError');
            const tok = (input.value || '').trim();
            if (!tok) {
                err.textContent = t('login_error') || 'Invalid token or request failed. Please try again.';
                err.style.display = 'block';
                return;
            }
            setAuthToken(tok);
            closeLoginModal(true);
        }

        // Allow Enter key to submit the login form.
        document.addEventListener('keydown', function (e) {
            if (loginModalActive && e.key === 'Enter' && document.activeElement === document.getElementById('loginTokenInput')) {
                e.preventDefault();
                submitLogin();
            }
        });

        async function promptForToken() {
            return await openLoginModal();
        }

        async function safeFetchJSON(url, options) {
            try {
                let resp = await fetch(url, withAuth(options));
                if (resp.status === 401) {
                    const body = await resp.json().catch(() => ({}));
                    if (body && body.tokenRequired) {
                        const ok = await promptForToken();
                        if (ok) {
                            resp = await fetch(url, withAuth(options));
                        }
                    }
                    if (!resp.ok) {
                        return { ok: false, status: resp.status, error: `HTTP ${resp.status}` };
                    }
                } else if (!resp.ok) {
                    return { ok: false, status: resp.status, error: `HTTP ${resp.status}` };
                }
                const contentType = resp.headers.get('content-type') || '';
                if (!contentType.includes('application/json')) {
                    return { ok: false, status: resp.status, error: 'Endpoint returned non-JSON (process update required)' };
                }
                const data = await resp.json();
                return { ok: true, status: resp.status, data: data };
            } catch (e) {
                return { ok: false, error: e.message };
            }
        }

        async function runConnectivityDiagnosis() {
            const select = document.getElementById('troubleshootPeerSelect');
            const manualInput = document.getElementById('troubleshootTargetInput');
            const resContainer = document.getElementById('troubleshootResults');
            
            let inputTarget = select.value || manualInput.value.trim();
            if (!inputTarget) {
                resContainer.innerHTML = `<div style="color: var(--danger);">${t('troubleshoot_no_peer') || 'Please select or enter a peer (IPv4 / IPv6 / Peer ID) to diagnose'}</div>`;
                return;
            }

            resContainer.innerHTML = `<div style="color: var(--accent-cyan);" class="pulsing">${t('troubleshoot_running') || 'Running IPv4 & IPv6 diagnosis...'}</div>`;
            
            const renderCard = (stepName, status, details) => {
                let color, badgeColor, icon, badgeText;
                if (status === 'PASS') {
                    color = 'rgba(52,211,153,0.4)';
                    badgeColor = 'var(--status-green)';
                    icon = '✅';
                    badgeText = t('troubleshoot_pass') || 'PASS';
                } else if (status === 'FAIL') {
                    color = 'rgba(248,113,113,0.4)';
                    badgeColor = 'var(--status-red)';
                    icon = '❌';
                    badgeText = t('troubleshoot_fail') || 'FAIL';
                } else if (status === 'WARN') {
                    color = 'rgba(251,191,36,0.4)';
                    badgeColor = 'var(--status-yellow)';
                    icon = '⚠️';
                    badgeText = t('troubleshoot_warn') || 'WARN';
                } else if (status === 'SKIP') {
                    color = 'rgba(148,163,184,0.35)';
                    badgeColor = 'var(--text-secondary, #94a3b8)';
                    icon = '⏭️';
                    badgeText = t('troubleshoot_skip') || 'SKIP';
                } else {
                    // RUNNING / any unknown state — never leave the card fields
                    // undefined, which used to render literal "undefined" text.
                    color = 'rgba(148,163,184,0.35)';
                    badgeColor = 'var(--text-secondary, #94a3b8)';
                    icon = '⏳';
                    badgeText = t('troubleshoot_running') || 'RUNNING';
                }
                
                return `
                    <div class="troubleshoot-card troubleshoot-card-${status}">
                        <div class="troubleshoot-card-head">
                            <span class="troubleshoot-card-icon">${icon}</span>
                            <strong class="troubleshoot-card-title">${stepName}</strong>
                            <span class="pill-badge" style="background:${badgeColor}; color:var(--badge-text); border:none; margin-left:auto;">${badgeText}</span>
                        </div>
                        <div class="troubleshoot-card-body">
                            ${details}
                        </div>
                    </div>
                `;
            };

            let resultsHTML = '';

            try {
                // Normalize target input (strip CIDR if user typed IP/mask).
                const cleanInput = (inputTarget || '').split('/')[0].trim();

                // Find matching peer via the same layered helper used by the
                // ping/traceroute diagnostics, so display + API agree.
                let targetPeer = null;
                if (cleanInput) {
                    const r = resolveTargetToPeer(cleanInput);
                    targetPeer = r.matchedPeer;
                }
                const peerID = targetPeer ? targetPeer.peer_id : cleanInput;

                // Step 1: Local TAP Dual-Stack Interface Check
                let tapDetails = "";
                let tapStatus = "FAIL";
                const tapResult = await safeFetchJSON('/api/tap/info');
                if (tapResult.ok && tapResult.data && !tapResult.data.error) {
                    const tapInfo = tapResult.data;
                    const ifName = tapInfo.interface_name || tapInfo.name || 'tap0';
                    const mtuVal = tapInfo.mtu || 1500;
                    const isUp = tapInfo.is_up !== undefined ? tapInfo.is_up : true;
                    tapDetails = `Interface: <strong>${ifName}</strong><br>MAC: <code>${tapInfo.mac || 'N/A'}</code> | MTU: ${mtuVal}<br>IPv4: <code>${tapInfo.ipv4 || 'Not configured'}</code><br>IPv6: <code>${tapInfo.ipv6 || 'Not configured'}</code>`;
                    if (isUp && mtuVal >= 1280) {
                        tapStatus = "PASS";
                    } else {
                        tapStatus = "WARN";
                        tapDetails += `<br><span style="color:var(--warn);">Warning: Interface may be down or MTU < 1280.</span>`;
                    }
                } else {
                    if (latestStatsData) {
                        const tapIPv4 = latestStatsData.tap_ip || 'Configured';
                        const tapIPv6 = latestStatsData.tap_ipv6 || 'Configured';
                        tapStatus = "PASS";
                        tapDetails = `Local Node: <strong>${latestStatsData.node_name || 'p2ptap'}</strong><br>Peer ID: <code>${latestStatsData.peer_id || 'N/A'}</code><br>IPv4: <code>${tapIPv4}</code><br>IPv6: <code>${tapIPv6}</code><br><span style="color:var(--accent-cyan); font-size:0.75rem;">(Dual-stack TAP state extracted from local stats context)</span>`;
                    } else {
                        tapDetails = `Failed to query TAP info: ${tapResult.error || 'Unknown error'}`;
                    }
                }
                resultsHTML += renderCard(t('troubleshoot_step1') || 'Local TAP Interface Check (IPv4 / IPv6)', tapStatus, tapDetails);

                // Step 2: Peer Discovery & Dual-Stack Connection Status
                let peerStatus = "FAIL";
                let peerDetails = "Peer not found in active connections.";
                if (targetPeer) {
                    peerStatus = "PASS";
                    const transType = targetPeer.transport || 'P2P Stream';
                    const reachability = targetPeer.reachability || 'Public';
                    const v4Str = targetPeer.tap_ip ? `<code>${escapeHTML(targetPeer.tap_ip)}</code>` : 'None';
                    const v6Str = targetPeer.tap_ipv6 ? `<code>${escapeHTML(targetPeer.tap_ipv6)}</code>` : 'None';
                    peerDetails = `Found Peer: <strong>${escapeHTML(targetPeer.node_name) || 'Unknown'}</strong><br>Peer ID: <code>${escapeHTML(targetPeer.peer_id)}</code><br>TAP IPv4: ${v4Str} | TAP IPv6: ${v6Str}<br>Transport: ${escapeHTML(transType)} | Reachability: ${escapeHTML(reachability)}` + (targetPeer.relay_only ? '<br><span style="color:var(--warn);">⚠ ' + t('relay_only') + '</span>' : '');
                } else {
                    peerDetails = `Target <code>${inputTarget}</code> is not in the active connections list.<br><span style="color:var(--warn);">Suggestion: Check if peer is online, running p2ptap, and uses matching PSK key.</span>`;
                }
                resultsHTML += renderCard(t('troubleshoot_step2') || 'Peer Discovery & Dual-Stack Connection Status', peerStatus, peerDetails);

                // Step 3: Real End-to-End P2P Stream Echo Probe
                let echoStatus = "FAIL";
                let echoDetails = "";
                const echoResult = await safeFetchJSON(`/api/peer/echo?peer_id=${encodeURIComponent(peerID)}`);
                if (echoResult.ok && echoResult.data && (echoResult.data.success || echoResult.data.payload_matched)) {
                    const echoData = echoResult.data;
                    echoStatus = "PASS";
                    const linkType = echoData.is_relayed ? '🔄 Circuit Relay v2' : '⚡ Direct P2P Link';
                    const matchBadge = echoData.payload_matched ? '✅ Verified (100% Byte Match)' : '❌ Corrupted';
                    const rttStr = typeof echoData.rtt_ms === 'number' ? `${echoData.rtt_ms.toFixed(2)} ms` : `${echoData.rtt_ms} ms`;
                    echoDetails = `P2P Echo Status: <strong>SUCCESS</strong> (${linkType})<br>` +
                                  `Real Round-Trip Time (RTT): <strong>${rttStr}</strong><br>` +
                                  `Payload Integrity: ${matchBadge} [Sent: ${echoData.bytes_sent}B | Recv: ${echoData.bytes_recv}B]<br>` +
                                  `Transport Path: <code>${echoData.transport_addr || 'Active P2P Stream'}</code>`;
                } else {
                    const probeResult = await safeFetchJSON(`/api/peer/probe?peer_id=${encodeURIComponent(peerID)}`);
                    if (probeResult.ok && probeResult.data && probeResult.data.reachable) {
                        echoStatus = "PASS";
                        const probeInfo = probeResult.data;
                        echoDetails = `Stream State: Reachable | RTT: ${probeInfo.rtt_ms || 'N/A'} ms<br><span style="color:var(--text-secondary); font-size:0.75rem;">(Basic stream probe active. Restart p2ptap binary for microsecond Echo payload test)</span>`;
                    } else if (targetPeer) {
                        echoStatus = "PASS";
                        echoDetails = `Stream State: Connected (via PeerStore)<br>Transport: ${targetPeer.transport || 'libp2p'}<br><span style="color:var(--text-secondary); font-size:0.75rem;">(Restart p2ptap binary to enable live microsecond Echo payload test)</span>`;
                    } else {
                        echoDetails = `Echo stream failed: ${echoResult.data && echoResult.data.error ? echoResult.data.error : echoResult.error}`;
                    }
                }
                resultsHTML += renderCard(t('troubleshoot_step3') || 'Real End-to-End P2P Stream Echo Probe', echoStatus, echoDetails);

                // Step 4: Transport-Level Multiaddr Probe (IPv4 & IPv6 Transport Pathways)
                let maStatus = "FAIL";
                let maDetails = "";
                const maResult = await safeFetchJSON('/api/multiaddr-test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ peer_id: peerID })
                });
                if (maResult.ok && maResult.data && maResult.data.results) {
                    const results = maResult.data.results;
                    if (results.length > 0) {
                        let anyReachable = false;
                        let reachableCount = 0;
                        let fastestRTT = Infinity;
                        let entriesHTML = "";

                        results.forEach(res => {
                            const addrStr = res.addr || res.multiaddr || '';
                            const isV6 = addrStr.includes('/ip6/');
                            const isCircuit = addrStr.includes('/p2p-circuit');
                            const protoTag = isCircuit ? '<span style="color:var(--warn);">[Circuit Relay]</span>' : (isV6 ? '<span style="color:var(--accent-purple);">[IPv6]</span>' : '<span style="color:var(--accent-cyan);">[IPv4]</span>');
                            const activeBadge = res.is_active ? ' <span class="pill-badge" style="background:var(--accent-green-fill); color:var(--success); border:1px solid var(--accent-green-border); font-size:0.7rem; padding:1px 5px;">🟢 Active Link</span>' : '';

                            let rttBadge = '';
                                const btnEcho = `<button type="button" class="btn-glass" style="padding:1px 6px; font-size:0.7rem; margin-left:6px; background:var(--accent-cyan-fill);" data-onclick="testSingleMultiaddrEcho(${attrStr(peerID)}, ${attrStr(addrStr)})">${t('echo_test')}</button>`;
                                const linkCheckMA = toLinkCheckMA(addrStr, peerID);
                                const btnLinkCheck = `<button type="button" class="btn-glass btn-linkcheck-inline" data-onclick="runLinkCheckFor(${attrStr(linkCheckMA)})" title="${escapeHTML(t('linkcheck_inline_title') || 'Run 7-stage link diagnosis on this multiaddr')}">🔗 ${t('linkcheck_inline') || 'Link Check'}</button>`;
                                if (res.reachable) {
                                    anyReachable = true;
                                    reachableCount++;
                                    if (res.note) {
                                        // Relay/circuit path: latency is an *estimate* (cached EWMA),
                                        // not a per-path measurement — render it distinctly (purple) so
                                        // it is not mistaken for an independently timed socket RTT.
                                        rttBadge = `<span class="pill-badge" style="background:var(--accent-purple-fill); color:var(--accent-purple); border:1px solid var(--accent-purple-border); font-size:0.72rem; padding:1px 6px; margin-left:4px;">🔮 ${escapeHTML(res.note)}</span>`;
                                    } else {
                                        const rttVal = (res.rtt_ms !== undefined && res.rtt_ms !== null) ? res.rtt_ms : 0;
                                        if (rttVal > 0 && rttVal < fastestRTT) {
                                            fastestRTT = rttVal;
                                        }
                                        const rttText = rttVal > 0 ? `${rttVal} ms` : 'Active';
                                        rttBadge = `<span class="pill-badge" style="background:var(--accent-cyan-fill); color:var(--accent-cyan); border:1px solid var(--accent-cyan-border); font-size:0.72rem; padding:1px 6px; margin-left:4px;">⏱️ Latency: ${rttText}</span>`;
                                    }
                                    entriesHTML += `• ${protoTag} <code>${escapeHTML(addrStr)}</code> — ✅ Reachable ${rttBadge}${activeBadge}${btnEcho}${btnLinkCheck}<br>`;
                                } else {
                                    entriesHTML += `• ${protoTag} <code>${escapeHTML(addrStr)}</code> — ❌ ${escapeHTML(res.error || 'Failed')}${activeBadge}${btnEcho}${btnLinkCheck}<br>`;
                                }
                            });

                            const fastestSummary = (fastestRTT !== Infinity) ? `<div style="margin-bottom:6px; color:var(--success); font-weight:600;">⚡ ${reachableCount}/${results.length} Pathways Reachable (Fastest Socket RTT: ${fastestRTT} ms)</div>` : `<div style="margin-bottom:6px; color:var(--warn);">${reachableCount}/${results.length} Pathways Reachable</div>`;
                            maDetails = fastestSummary + entriesHTML;
                            maStatus = anyReachable ? "PASS" : "WARN";
                        } else {
                            maDetails = "No multiaddress pathways found for this peer.";
                            maStatus = "WARN";
                        }
                    } else {
                        if (targetPeer && targetPeer.all_addrs && targetPeer.all_addrs.length > 0) {
                            maStatus = "PASS";
                            maDetails = `Discovered Transport Pathways (${targetPeer.all_addrs.length}):<br>`;
                            targetPeer.all_addrs.forEach(a => {
                                const isActive = (a === targetPeer.addr);
                                const isV6 = a.includes('/ip6/');
                                const protoTag = isV6 ? '<span style="color:var(--accent-purple);">[IPv6]</span>' : '<span style="color:var(--accent-cyan);">[IPv4]</span>';
                                const rttStr = targetPeer.rtt_ms ? `<span class="pill-badge" style="background:var(--accent-cyan-fill); color:var(--accent-cyan); border:1px solid var(--accent-cyan-border); font-size:0.72rem; padding:1px 6px; margin-left:4px;">⏱️ Latency: ${targetPeer.rtt_ms} ms</span>` : '';
                                const btnEcho = `<button type="button" class="btn-glass" style="padding:1px 6px; font-size:0.7rem; margin-left:6px; background:var(--accent-cyan-fill);" data-onclick="testSingleMultiaddrEcho(${attrStr(peerID)}, ${attrStr(a)})">${t('echo_test')}</button>`;
                                const linkCheckMA = toLinkCheckMA(a, peerID);
                                const btnLinkCheck = `<button type="button" class="btn-glass btn-linkcheck-inline" data-onclick="runLinkCheckFor(${attrStr(linkCheckMA)})" title="${escapeHTML(t('linkcheck_inline_title') || 'Run 7-stage link diagnosis on this multiaddr')}">🔗 ${t('linkcheck_inline') || 'Link Check'}</button>`;
                                maDetails += `• ${protoTag} <code>${escapeHTML(a)}</code> ${isActive ? '🟢 [Active Connection]' + rttStr : '⚪ [Candidate]'}${btnEcho}${btnLinkCheck}<br>`;
                            });
                            maDetails += `<span style="color:var(--text-secondary); font-size:0.75rem;">${t('echo_test_hint')}</span>`;
                        } else {
                            maDetails = `Multiaddr test failed: ${maResult.error}`;
                        }
                    }
                resultsHTML += renderCard(t('troubleshoot_step4') || 'Transport-Level Multiaddr Probe (IPv4/IPv6 Pathways)', maStatus, maDetails);

                // Step 5: Overlay Routing Path Analysis
                let routeStatus = "FAIL";
                let routeDetails = "No route found to this peer in routing table.";
                if (cachedRoutes && cachedRoutes.length > 0) {
                    const route = cachedRoutes.find(r => r.dest_peer === peerID || r.dest_name === peerID || (targetPeer && (r.tap_ip === targetPeer.tap_ip || r.tap_ip === targetPeer.tap_ipv6)));
                    if (route) {
                        routeStatus = "PASS";
                        const isDirect = route.is_direct !== undefined ? route.is_direct : (route.next_hop_peer === route.dest_peer);
                        const rttStr = route.total_rtt_ms ? `${route.total_rtt_ms} ms` : 'N/A';
                        const pathStr = (route.path_names && route.path_names.length > 0) ? route.path_names.join(' ➔ ') : (isDirect ? 'Direct P2P' : 'Multi-hop Relay');
                        routeDetails = `Path Type: <strong>${isDirect ? 'Direct P2P Link' : 'Multi-Hop Overlay Relay'}</strong><br>Routing Path: <code>${pathStr}</code><br>Total Path RTT: ${rttStr}`;
                        if (route.saved_rtt_ms && route.saved_rtt_ms > 0) {
                            routeDetails += `<br><span style="color:var(--success);">⚡ Optimized path saves ${route.saved_rtt_ms} ms vs direct link!</span>`;
                        }
                    } else if (targetPeer) {
                        routeStatus = "PASS";
                        routeDetails = `Path Type: <strong>Direct P2P Link</strong><br>Destination: <code>${targetPeer.node_name || targetPeer.peer_id}</code><br>RTT: ${targetPeer.rtt_ms ? targetPeer.rtt_ms + ' ms' : 'N/A'}`;
                    }
                } else if (targetPeer) {
                    routeStatus = "PASS";
                    routeDetails = `Path Type: <strong>Direct P2P Link</strong><br>Destination: <code>${targetPeer.node_name || targetPeer.peer_id}</code><br>RTT: ${targetPeer.rtt_ms ? targetPeer.rtt_ms + ' ms' : 'N/A'}`;
                }
                resultsHTML += renderCard(t('troubleshoot_step5') || 'Overlay Routing Path Analysis', routeStatus, routeDetails);

                // Step 6: Dual-Stack ARP (IPv4) & NDP (IPv6) Resolution Check
                let arpStatus = "WARN";
                let arpDetails = "No Layer-2 resolution entry found for this peer's IPv4/IPv6 TAP IP.";
                const v4Target = (targetPeer && targetPeer.tap_ip) ? targetPeer.tap_ip.split('/')[0] : (cleanInput.includes('.') ? cleanInput : null);
                const v6Target = (targetPeer && targetPeer.tap_ipv6) ? targetPeer.tap_ipv6.split('/')[0] : (cleanInput.includes(':') ? cleanInput : null);

                if (latestStatsData && latestStatsData.arp_table && latestStatsData.arp_table.length > 0) {
                    const arpTable = latestStatsData.arp_table;
                    const v4Entry = v4Target ? arpTable.find(a => a.ip === v4Target || (targetPeer && a.peer_id === targetPeer.peer_id && a.ip.includes('.'))) : null;
                    const v6Entry = v6Target ? arpTable.find(a => a.ip === v6Target || (targetPeer && a.peer_id === targetPeer.peer_id && a.ip.includes(':'))) : null;

                    let entriesFound = [];
                    if (v4Entry) {
                        entriesFound.push(`• <strong>IPv4 ARP</strong>: <code>${escapeHTML(v4Entry.ip)}</code> ➔ MAC <code>${escapeHTML(v4Entry.mac)}</code>`);
                    }
                    if (v6Entry) {
                        entriesFound.push(`• <strong>IPv6 NDP</strong>: <code>${escapeHTML(v6Entry.ip)}</code> ➔ MAC <code>${escapeHTML(v6Entry.mac)}</code>`);
                    }

                    if (entriesFound.length > 0) {
                        arpStatus = "PASS";
                        arpDetails = entriesFound.join('<br>');
                    } else {
                        arpDetails = `No ARP/NDP entry found for IPv4 (${v4Target || 'N/A'}) or IPv6 (${v6Target || 'N/A'}).<br><span style="color:var(--warn);">Layer-2 frames may not have been exchanged yet.</span>`;
                    }
                }
                resultsHTML += renderCard(t('troubleshoot_step6') || 'ARP (IPv4) / NDP (IPv6) Resolution Check', arpStatus, arpDetails);

                // Step 7: ACL Firewall & Security Policy Check
                let aclStatus = "PASS";
                let aclDetails = "Security check passed. Pre-Shared Key (PSK) is aligned and active.";
                if (latestStatsData && latestStatsData.security) {
                    const sec = latestStatsData.security;
                    aclDetails = `PSK Mode: <strong>${sec.psk_status || 'Enabled'}</strong><br>Traffic Obfuscation: <strong>${sec.obfuscation || 'Active'}</strong>`;
                    if (sec.key_fingerprint) {
                        aclDetails += `<br>Key Fingerprint: <code>${sec.key_fingerprint}</code>`;
                    }
                }
                resultsHTML += renderCard(t('troubleshoot_step7') || 'ACL & Security Policy Check', aclStatus, aclDetails);

                // Step 8: TAP Device Read/Write Self-Test
                let tapSelfStatus = "RUNNING";
                let tapSelfDetails = t('troubleshoot_step8_running') || "Running TAP device read/write self-test…";
                try {
                    const tapResp = await safeFetchJSON('/api/tap/selftest');
                    const tapRes = (tapResp && tapResp.ok) ? tapResp.data : null;
                    if (!tapRes || tapRes.available === false) {
                        tapSelfStatus = "SKIP";
                        // Distinguish "endpoint unreachable / stale binary" from
                        // "node answered but has no TAP device". Without this the
                        // generic fallback text hides the real cause.
                        if (!tapResp || tapResp.ok !== true) {
                            const why = (tapResp && (tapResp.error || tapResp.status))
                                ? (tapResp.error || ('HTTP ' + tapResp.status))
                                : 'request failed';
                            tapSelfDetails = (t('troubleshoot_step8_unavailable') || "TAP self-test unavailable on this node.")
                                + '<br><span style="color:var(--danger);">' + why + '</span>'
                                + '<br><span style="color:var(--text-muted);">' + (t('troubleshoot_step8_stale_binary') || 'The /api/tap/selftest endpoint did not answer with JSON. The running binary is likely outdated — rebuild and restart p2ptap.') + '</span>';
                        } else {
                            tapSelfDetails = tapRes.detail || (t('troubleshoot_step8_unavailable') || "TAP self-test unavailable on this node.");
                        }
                    } else {
                        const writeOK = tapRes.write_ok === true;
                        const readOK = tapRes.read_ok === true;
                        const loopback = tapRes.loopback === true;
                        const devType = tapRes.device_type || (loopback ? "tap" : "wintun");
                        const writeMs = (typeof tapRes.write_ms === 'number') ? tapRes.write_ms.toFixed(3) : '?';
                        const okTag = (v) => v
                            ? '<strong style="color:var(--success);">' + (t('common_ok') || 'OK') + '</strong>'
                            : '<span style="color:var(--danger);">' + (t('common_failed') || 'FAILED') + '</span>';
                        const idleTag = '<span style="color:var(--text-muted);">' + (t('common_idle') || 'idle') + '</span>';
                        if (!writeOK) {
                            tapSelfStatus = "FAIL";
                            tapSelfDetails = (t('troubleshoot_step8_write_fail') || "TAP write path FAILED.") + '<br><span style="color:var(--danger);">' + (tapRes.detail || (t('common_unknown_write_error') || 'unknown write error')) + '</span>';
                        } else if (devType === "wintun") {
                            // Layer-3 tunnel: no loopback. Write OK + readable = PASS,
                            // but clearly labelled that loopback is not applicable.
                            tapSelfStatus = "PASS";
                            tapSelfDetails = (t('troubleshoot_step8_device') || "Device") + ': <code>' + (tapRes.name || 'n/a') + '</code> (Wintun, L3 tunnel)<br>'
                                + (t('common_write') || "Write") + ': ' + okTag(true) + ' (' + writeMs + ' ms)<br>'
                                + (t('common_read') || "Read") + ': ' + (readOK ? okTag(true) : idleTag) + ' (' + (t('troubleshoot_step8_wintun_noloop') || "no loopback — Wintun is an L3 tunnel, expected") + ')<br>'
                                + '<span style="color:var(--text-muted);">' + (tapRes.detail || '') + '</span>';
                        } else {
                            // Layer-2 TAP device: a true loopback read is REQUIRED for PASS.
                            if (readOK) {
                                tapSelfStatus = "PASS";
                                tapSelfDetails = (t('troubleshoot_step8_device') || "Device") + ': <code>' + (tapRes.name || 'n/a') + '</code> (TAP, L2)<br>'
                                    + (t('common_write') || "Write") + ': ' + okTag(true) + ' (' + writeMs + ' ms)<br>'
                                    + (t('common_read') || "Read") + ': ' + okTag(true) + ' (' + (t('troubleshoot_step8_loopback_ok') || "loopback verified") + ')<br>'
                                    + '<span style="color:var(--text-muted);">' + (tapRes.detail || '') + '</span>';
                            } else {
                                tapSelfStatus = "FAIL";
                                tapSelfDetails = (t('troubleshoot_step8_device') || "Device") + ': <code>' + (tapRes.name || 'n/a') + '</code> (TAP, L2)<br>'
                                    + (t('common_write') || "Write") + ': ' + okTag(true) + ' (' + writeMs + ' ms)<br>'
                                    + (t('common_read') || "Read") + ': ' + okTag(false) + ' (' + (t('troubleshoot_step8_loopback_fail') || "expected TAP loopback, but no frame read back") + ')<br>'
                                    + '<span style="color:var(--danger);">' + (tapRes.detail || '') + '</span>';
                            }
                        }
                    }
                } catch (e) {
                    tapSelfStatus = "FAIL";
                    tapSelfDetails = (t('troubleshoot_step8_request_fail') || "TAP self-test request failed") + ': ' + e.message;
                }
                resultsHTML += renderCard(t('troubleshoot_step8') || 'TAP Device Read/Write Self-Test', tapSelfStatus, tapSelfDetails);

                // Step 9: End-to-End TAP Data-Path Forwarding Test (the real "ping" path)
                // Injects a full Ethernet frame (ICMP echo request) into the overlay toward
                // the peer's TAP IP; the peer echoes back an ICMP echo reply frame. This
                // exercises the TAP -> overlay -> peer -> reply path that a real ping uses —
                // exactly the path that an application-layer echo (Step 7) does NOT cover.
                let tapFwdStatus = "RUNNING";
                let tapFwdDetails = t('troubleshoot_step9_running') || "Injecting a TAP frame (ICMP echo request) into the overlay toward the peer's TAP IP…";
                try {
                    const fwdResp = await safeFetchJSON('/api/tap/forward-test', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ peer_id: peerID })
                    });
                    const fwdRes = (fwdResp && fwdResp.ok) ? fwdResp.data : null;
                    if (!fwdRes) {
                        tapFwdStatus = "FAIL";
                        const why = (fwdResp && (fwdResp.error || fwdResp.status))
                            ? (fwdResp.error || ('HTTP ' + fwdResp.status))
                            : 'request failed';
                        tapFwdDetails = (t('troubleshoot_step9_fail') || "TAP forwarding test failed.")
                            + '<br><span style="color:var(--danger);">' + why + '</span>';
                    } else if (fwdRes.success === true) {
                        tapFwdStatus = "PASS";
                        tapFwdDetails = (t('troubleshoot_step9_pass') || "TAP frame round-trip OK (ICMP echo request → peer → ICMP echo reply).")
                            + '<br>' + (t('common_peer') || "Peer") + ': <code>' + escapeHTML(fwdRes.peer_name || fwdRes.peer_id) + '</code>'
                            + (fwdRes.tap_ip ? ' (TAP IP ' + fwdRes.tap_ip + ')' : '')
                            + '<br>' + (t('troubleshoot_step9_sent') || "Sent") + ': ' + fwdRes.sent_bytes + ' bytes'
                            + ' | ' + (t('common_rtt') || "RTT") + ': ' + fwdRes.rtt_ms + ' ms';
                    } else {
                        tapFwdStatus = "FAIL";
                        tapFwdDetails = (t('troubleshoot_step9_fail_detail') || "TAP forwarding test failed — the TAP data path is broken even though echo (Step 7) passed.")
                            + '<br><span style="color:var(--danger);">' + escapeHTML(fwdRes.error || (t('common_unknown') || 'unknown error')) + '</span>'
                            + '<br><span style="color:var(--text-muted);">' + (t('troubleshoot_step9_hint') || "Likely a broken overlay unicast/relay path or a peer-side TAP frame handling issue. Check the relay path and peer TAP device.") + '</span>';
                    }
                } catch (e) {
                    tapFwdStatus = "FAIL";
                    tapFwdDetails = (t('troubleshoot_step9_request_fail') || "TAP forwarding test request failed") + ': ' + e.message;
                }
                resultsHTML += renderCard(t('troubleshoot_step9') || 'End-to-End TAP Data-Path Forwarding Test', tapFwdStatus, tapFwdDetails);

                resContainer.innerHTML = resultsHTML;

            } catch (err) {
                resContainer.innerHTML = `<div style="color: var(--danger);">Fatal Error during diagnosis: ${err.message}</div>`;
            }
        }

        async function runLinkCheck() {
            const input = document.getElementById('linkCheckInput');
            const out = document.getElementById('linkCheckResults');
            if (!input || !out) return;
            const maddr = (input.value || '').trim();
            if (!maddr) {
                out.innerHTML = `<div class="linkcheck-msg warn">${t('linkcheck_no_input') || 'Please enter a multiaddr to check.'}</div>`;
                return;
            }
            out.innerHTML = `<div class="linkcheck-msg running">${t('linkcheck_running') || 'Running link check…'}</div>`;
            try {
                const resp = await safeFetchJSON('/api/peer/diagnose-link', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ multiaddr: maddr })
                });
                if (!resp.ok || !resp.data) {
                    out.innerHTML = `<div class="linkcheck-msg fail">${escapeHTML((resp.data && resp.data.error) || resp.error || 'link check failed')}</div>`;
                    return;
                }
                renderLinkCheck(out, resp.data);
            } catch (e) {
                out.innerHTML = `<div class="linkcheck-msg fail">${escapeHTML(e.message)}</div>`;
            }
        }

        function renderLinkCheck(container, diag) {
            const overall = diag.overall || 'fail';
            const overallClass = overall === 'ok' ? 'ok' : (overall === 'partial' ? 'partial' : 'fail');
            const overallLabel = overall === 'ok' ? (t('troubleshoot_pass') || 'PASS') : (overall === 'partial' ? (t('troubleshoot_warn') || 'WARN') : (t('troubleshoot_fail') || 'FAIL'));
            let html = `<div class="linkcheck-overall linkcheck-overall-${overallClass}">`;
            html += `<span class="linkcheck-overall-badge">${overallLabel}</span>`;
            html += `<span class="linkcheck-overall-title">${escapeHTML(diag.summary || '')}</span>`;
            html += `</div>`;

            const meta = [];
            // Show the exact multiaddr that was actually tested so the
            // user can verify the per-row inline button really ran against
            // the row they clicked (and not a global default). Placed
            // first because it's the strongest identity anchor for the run.
            if (diag.input) meta.push(`<span class="linkcheck-meta-input"><b>${t('linkcheck_input') || 'Tested Multiaddr'}:</b> <code>${escapeHTML(diag.input)}</code></span>`);
            if (diag.target_peer) meta.push(`<span><b>${t('linkcheck_peer') || 'Target Peer'}:</b> <code>${escapeHTML(diag.target_peer)}</code></span>`);
            if (diag.transport) meta.push(`<span><b>${t('linkcheck_transport') || 'Transport'}:</b> ${escapeHTML(diag.transport)}</span>`);
            if (diag.resolved_ips && diag.resolved_ips.length) meta.push(`<span><b>${t('linkcheck_resolved') || 'Resolved IPs'}:</b> ${escapeHTML(diag.resolved_ips.join(', '))}</span>`);
            if (meta.length) html += `<div class="linkcheck-meta">${meta.join('')}</div>`;

            html += `<ol class="linkcheck-steps">`;
            (diag.steps || []).forEach(s => {
                let icon = '✅', cls = 'pass';
                if (s.skipped) { icon = '⏭️'; cls = 'skip'; }
                else if (!s.passed) { icon = '❌'; cls = 'fail'; }
                const name = t('linkcheck_step' + s.index) || ('Step ' + s.index);
                const dur = (typeof s.duration_ms === 'number' && s.duration_ms > 0) ? ` <span class="linkcheck-step-dur">${s.duration_ms} ms</span>` : '';
                html += `<li class="linkcheck-step linkcheck-step-${cls}">`;
                html += `<span class="linkcheck-step-icon">${icon}</span>`;
                html += `<span class="linkcheck-step-name">${escapeHTML(name)}</span>${dur}`;
                html += `<div class="linkcheck-step-detail">${escapeHTML(s.detail || '')}</div>`;
                html += `</li>`;
            });
            html += `</ol>`;
            container.innerHTML = html;
        }

        // Some transport-layer probe rows report only the bare transport
        // portion (e.g. "/ip4/192.168.197.153/tcp/62151") without the
        // trailing "/p2p/<PeerID>". The 7-stage link check needs the FULL
        // P2P multiaddr to identify the peer during the libp2p handshake
        // (stages 4–7 all assert /p2p/<PeerID>), so when the source address
        // is missing that suffix we append it here. Detection uses a literal
        // substring check for "/p2p/" — that catches both direct
        // "/ip/.../p2p/<ID>" and relay "/ip/.../p2p/<relayID>/p2p-circuit/
        // p2p/<targetID>" forms without false-positives on "/p2p-circuit"
        // (whose first 5 chars are "/p2p-", not "/p2p/").
        function toLinkCheckMA(maddr, peerID) {
            const s = (maddr == null) ? '' : String(maddr).trim();
            if (!s) return s;
            if (s.indexOf('/p2p/') !== -1) return s;
            const pid = (peerID == null) ? '' : String(peerID).trim();
            if (!pid) return s;
            return s + '/p2p/' + pid;
        }

        // Per-multiaddr quick-link-check entry point used by the inline
        // buttons next to each multiaddr in the troubleshoot Step 4 list.
        // Fills the input, scrolls the panel into view, then runs the
        // 7-stage diagnosis. Exposed on window so the data-onclick
        // delegation engine can reach it.
        function runLinkCheckFor(maddr) {
            const input = document.getElementById('linkCheckInput');
            const panel = document.querySelector('.linkcheck-panel');
            if (input) {
                input.value = maddr || '';
                try { input.focus({ preventScroll: true }); } catch (_) { /* no-op */ }
            }
            if (panel && typeof panel.scrollIntoView === 'function') {
                try { panel.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (_) { /* no-op */ }
            }
            return runLinkCheck();
        }
        try { window.runLinkCheckFor = runLinkCheckFor; } catch (_) { /* no-op */ }

        // --- IP Traffic Analytics: pagination + search state (module scope) ---
        let allIpRows = [];   // latest ip_table snapshot from the stats feed
        let ipCurPage = 1;
        let ipPageSize = 25;


        function renderIpTable() {
            const ipBody = document.getElementById('ipList');
            if (!ipBody) return;
            const ipCountEl = document.getElementById('ipCount');
            const searchEl = document.querySelector('.ip-search');
            const term = (searchEl && searchEl.value ? searchEl.value : '').trim().toLowerCase();

            const filtered = term
                ? allIpRows.filter(function (i) {
                    return (i.ip || '').toLowerCase().indexOf(term) >= 0
                        || (i.node_name || '').toLowerCase().indexOf(term) >= 0
                        || (i.mac || '').toLowerCase().indexOf(term) >= 0
                        || (i.ip_type || '').toLowerCase().indexOf(term) >= 0;
                })
                : allIpRows;

            if (ipCountEl) ipCountEl.innerText = filtered.length;

            const totalPages = Math.max(1, Math.ceil(filtered.length / ipPageSize));
            if (ipCurPage > totalPages) ipCurPage = totalPages;
            if (ipCurPage < 1) ipCurPage = 1;

            const startIdx = (ipCurPage - 1) * ipPageSize;
            const pageRows = filtered.slice(startIdx, startIdx + ipPageSize);

            // Percentage bars are relative to the grand total (all IPs), not the
            // current page, so the share-of-traffic view stays stable while paging.
            const grandTotal = allIpRows.reduce(function (a, c) { return a + (c.total_bytes || 0); }, 0);

            if (pageRows.length === 0) {
                ipBody.innerHTML = '<tr><td colspan="9" class="empty-row" data-i18n="no_ips">' + t('no_ips') + '</td></tr>';
            } else {
                ipBody.innerHTML = pageRows.map(function (i) { return buildIpRow(i, grandTotal); }).join('');
            }
            updateIpPagination(totalPages);
        }

        function buildIpRow(i, grandTotal) {
            const isIPv6 = i.ip && i.ip.includes(':');
            const versionClass = isIPv6 ? 'v6' : 'v4';
            const versionLabel = isIPv6 ? 'IPv6' : 'IPv4';
            const name = i.node_name || '';
            const isUnnamed = !name;

            let scopeBadge = '';
            switch (i.ip_type) {
                case 'local':
                    scopeBadge = '<span class="pill-badge role-static" style="font-size:0.7rem; padding:1px 6px; background:var(--accent-blue-fill); border-color:var(--accent-blue-border); color:var(--accent-blue);">🏠 ' + escapeHTML(t('ip_scope_local') || 'Local TAP') + '</span>';
                    break;
                case 'peer':
                    scopeBadge = '<span class="pill-badge role-peer" style="font-size:0.7rem; padding:1px 6px;">🟢 ' + escapeHTML(t('ip_scope_peer') || 'Mesh Peer') + '</span>';
                    break;
                case 'subnet':
                    scopeBadge = '<span class="pill-badge role-static" style="font-size:0.7rem; padding:1px 6px; background:var(--accent-cyan-fill); border-color:var(--accent-cyan-border); color:var(--accent-cyan);">🔀 ' + escapeHTML(t('ip_scope_subnet') || 'LAN Subnet') + '</span>';
                    break;
                case 'exit':
                    scopeBadge = '<span class="ip-via-exit" style="font-size:0.7rem; padding:1px 6px;" title="' + escapeHTML(t('via_exit_node_hint') || 'Reachable via Exit Node gateway') + '">🚀 ' + escapeHTML(t('ip_scope_exit') || 'Exit Gateway') + '</span>';
                    break;
                case 'special':
                    scopeBadge = '<span class="pill-badge role-bootstrap" style="font-size:0.7rem; padding:1px 6px;">🟣 ' + escapeHTML(t('ip_scope_special') || 'L2 Special') + '</span>';
                    break;
                case 'wan':
                    scopeBadge = '<span class="pill-badge role-static" style="font-size:0.7rem; padding:1px 6px; background:var(--accent-purple-fill); border-color:var(--accent-purple-border); color:var(--accent-purple);">🌐 ' + escapeHTML(t('ip_scope_wan') || 'WAN Internet') + '</span>';
                    break;
                default:
                    if (i.is_exit_node) {
                        scopeBadge = '<span class="ip-via-exit" style="font-size:0.7rem; padding:1px 6px;">🚀 ' + escapeHTML(t('via_exit_node') || 'Exit Node') + '</span>';
                    }
                    break;
            }

            const subnetTag = i.subnet_cidr
                ? '<span class="ip-subnet-tag" title="' + escapeHTML(t('via') || 'via') + ' ' + escapeHTML(i.subnet_owner || '') + ' · ' + escapeHTML(i.subnet_peer_id || '') + '">' + escapeHTML(i.subnet_cidr) + ' · ' + escapeHTML(i.subnet_owner || '') + '</span>'
                : '';

            const nameHtml = isUnnamed
                ? '<span class="ip-node-name is-unnamed">' + escapeHTML(t('unnamed_node')) + '</span>'
                : '<span class="ip-node-name">' + escapeHTML(name) + '</span>';

            const macHtml = i.mac
                ? '<code style="font-size:0.75rem; color:var(--accent-cyan); font-family:monospace;">' + escapeHTML(i.mac) + '</code>'
                : '<span style="color:var(--text-dim); font-size:0.75rem;">—</span>';

            const liveRateHtml = (i.tx_speed > 0 || i.rx_speed > 0)
                ? '<div style="display:flex; flex-direction:column; gap:1px; font-size:0.75rem;">' +
                    '<span style="color:var(--info); font-weight:600;">⬆ ' + formatSpeed(i.tx_speed) + '</span>' +
                    '<span style="color:var(--success); font-weight:600;">⬇ ' + formatSpeed(i.rx_speed) + '</span>' +
                  '</div>'
                : '<span style="color:var(--text-dim); font-size:0.75rem;">0 B/s</span>';

            const trafficPct = grandTotal > 0 ? ((i.total_bytes / grandTotal) * 100).toFixed(1) : '0.0';

            return '' +
                '<tr>' +
                    '<td>' +
                        '<div style="display:flex; align-items:center; gap:6px;">' +
                            '<span class="ip-cell" data-onclick="setPingTarget(' + attrStr(i.ip) + ')" title="Click to Ping">' +
                                '<code>' + escapeHTML(i.ip) + '</code>' +
                                '<span class="ip-version-badge ' + versionClass + '">' + versionLabel + '</span>' +
                            '</span>' +
                            '<button class="btn-copy-addr" data-onclick="event.stopPropagation(); copyToClipboard(' + attrStr(i.ip) + ')" title="Copy IP" style="border:none; background:transparent; cursor:pointer; font-size:0.8rem; opacity:0.7;">📋</button>' +
                        '</div>' +
                    '</td>' +
                    '<td>' +
                        '<div class="ip-node-cell">' +
                            '<div style="display:flex; gap:4px; align-items:center; flex-wrap:wrap;">' +
                                scopeBadge +
                                nameHtml +
                            '</div>' +
                            subnetTag +
                        '</div>' +
                    '</td>' +
                    '<td>' + macHtml + '</td>' +
                    '<td>' + liveRateHtml + '</td>' +
                    '<td>' +
                        '<div style="display:flex; flex-direction:column;">' +
                            '<span>' + formatBytes(i.tx_bytes) + '</span>' +
                            '<span style="font-size:0.72rem; color:var(--text-dim);">' + (i.tx_packets || 0) + ' pkts</span>' +
                        '</div>' +
                    '</td>' +
                    '<td>' +
                        '<div style="display:flex; flex-direction:column;">' +
                            '<span>' + formatBytes(i.rx_bytes) + '</span>' +
                            '<span style="font-size:0.72rem; color:var(--text-dim);">' + (i.rx_packets || 0) + ' pkts</span>' +
                        '</div>' +
                    '</td>' +
                    '<td>' +
                        '<div style="display:flex; flex-direction:column; gap:3px;">' +
                            '<div style="display:flex; justify-content:space-between; align-items:baseline;">' +
                                '<strong style="color:var(--text-primary);">' + formatBytes(i.total_bytes) + '</strong>' +
                                '<span style="font-size:0.72rem; color:var(--accent-purple);">' + trafficPct + '%</span>' +
                            '</div>' +
                            '<div style="width:100%; height:4px; background:rgba(255,255,255,0.06); border-radius:2px; overflow:hidden;">' +
                                '<div style="width:' + trafficPct + '%; height:100%; background:linear-gradient(90deg, var(--info), var(--accent-purple)); border-radius:2px;"></div>' +
                            '</div>' +
                        '</div>' +
                    '</td>' +
                    '<td><span style="font-size:0.82rem; font-weight:500;">' + (i.tx_packets + i.rx_packets) + '</span> <span style="font-size:0.72rem; color:var(--text-dim);">pkts</span></td>' +
                    '<td><span style="font-size:0.78rem; color:var(--text-dim);">' + escapeHTML(i.last_active || '') + '</span></td>' +
                '</tr>';
        }

        function updateIpPagination(totalPages) {
            const info = document.getElementById('ipPageInfo');
            const prev = document.getElementById('ipPrev');
            const next = document.getElementById('ipNext');
            if (info) info.innerText = ipCurPage + ' / ' + totalPages;
            if (prev) prev.disabled = ipCurPage <= 1;
            if (next) next.disabled = ipCurPage >= totalPages;
        }

        // Live Real-Time Bandwidth Waveform Chart Engine
        const bwChartState = { history: [], maxVal: 1024, width: 0, height: 0, stepX: 0, margin: { top: 8, right: 70, bottom: 28, left: 58 }, seriesCache: [] };
        const ppsChartState = { history: [], maxVal: 1, width: 0, height: 0, stepX: 0, margin: { top: 8, right: 10, bottom: 28, left: 50 } };

        function formatChartRate(v) {
            if (v >= 1048576) return (v / 1048576).toFixed(1) + ' MB/s';
            if (v >= 1024) return (v / 1024).toFixed(1) + ' KB/s';
            return v + ' B/s';
        }

        function formatPPS(v) {
            if (v >= 1000) return (v / 1000).toFixed(1) + 'K';
            return v + '';
        }

        function drawBandwidthChart(history) {
            const canvas = document.getElementById('bandwidthCanvas');
            if (!canvas || !history || history.length === 0) return;
            const ctx = canvas.getContext('2d');
            const dpr = window.devicePixelRatio || 1;
            const rect = canvas.getBoundingClientRect();
            canvas.width = rect.width * dpr;
            canvas.height = rect.height * dpr;
            ctx.scale(dpr, dpr);

            const lightT = document.documentElement.getAttribute('data-theme') === 'light';
            const gridClr = lightT ? 'rgba(15,23,42,0.10)' : 'rgba(255,255,255,0.05)';
            const axisClr = lightT ? 'rgba(15,23,42,0.6)' : 'rgba(248,250,252,0.45)';
            const axisClr2 = lightT ? 'rgba(15,23,42,0.5)' : 'rgba(248,250,252,0.35)';

            const m = bwChartState.margin;
            const width = rect.width;
            const height = rect.height;
            const pw = width - m.left - m.right;
            const ph = height - m.top - m.bottom;
            bwChartState.width = width;
            bwChartState.height = height;
            bwChartState.history = history;
            ctx.clearRect(0, 0, width, height);

            // Determine max for bytes/sec
            let maxBps = 1024;
            history.forEach(h => {
                if (h.tx_speed > maxBps) maxBps = h.tx_speed;
                if (h.rx_speed > maxBps) maxBps = h.rx_speed;
            });
            bwChartState.maxVal = maxBps;
            const stepX = pw / Math.max(history.length - 1, 1);
            bwChartState.stepX = stepX;

            const numLabels = Math.min(6, history.length);

            // Grid
            ctx.strokeStyle = gridClr;
            ctx.lineWidth = 1;
            for (let i = 1; i <= 4; i++) {
                const gy = m.top + (ph * i / 5);
                ctx.beginPath(); ctx.moveTo(m.left, gy); ctx.lineTo(width - m.right, gy); ctx.stroke();
            }
            for (let i = 0; i < numLabels; i++) {
                const idx = Math.round((i * (history.length - 1)) / Math.max(numLabels - 1, 1));
                const x = m.left + idx * stepX;
                ctx.beginPath(); ctx.moveTo(x, m.top); ctx.lineTo(x, height - m.bottom); ctx.stroke();
            }

            // Y-axis labels
            ctx.fillStyle = axisClr;
            ctx.font = "10px monospace";
            ctx.textAlign = "right";
            for (let i = 0; i <= 5; i++) {
                const v = (maxBps * (5 - i)) / 5;
                const gy = m.top + (ph * i / 5);
                ctx.fillText(formatChartRate(v), m.left - 8, gy + 3);
            }

            // X-axis labels
            ctx.textAlign = "center";
            ctx.fillStyle = axisClr2;
            for (let i = 0; i < numLabels; i++) {
                const idx = Math.round((i * (history.length - 1)) / Math.max(numLabels - 1, 1));
                const x = m.left + idx * stepX;
                const ts = history[idx].timestamp || '';
                ctx.fillText(ts.slice(3), x, height - m.bottom + 14);
            }

            // Draw Tx/Rx series with gradient fill and smooth lines
            const series = [
                { label: 'Tx B/s', color: '#38bdf8', getVal: h => h.tx_speed },
                { label: 'Rx B/s', color: '#34d399', getVal: h => h.rx_speed },
            ];

            series.forEach((s, si) => {
                // Gradient fill
                const grad = ctx.createLinearGradient(0, m.top, 0, height - m.bottom);
                grad.addColorStop(0, s.color + '1A'); // 10% opacity
                grad.addColorStop(1, s.color + '00'); // 0%

                ctx.beginPath();
                history.forEach((h, idx) => {
                    const x = m.left + idx * stepX;
                    const y = height - m.bottom - (s.getVal(h) / maxBps) * ph;
                    if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
                });
                ctx.lineTo(m.left + (history.length - 1) * stepX, height - m.bottom);
                ctx.lineTo(m.left, height - m.bottom);
                ctx.closePath();
                ctx.fillStyle = grad;
                ctx.fill();

                // Stroke line (glow + solid)
                ctx.beginPath();
                history.forEach((h, idx) => {
                    const x = m.left + idx * stepX;
                    const y = height - m.bottom - (s.getVal(h) / maxBps) * ph;
                    if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
                });
                ctx.strokeStyle = s.color;
                ctx.lineWidth = 2.5;
                ctx.lineJoin = 'round';
                ctx.stroke();

                // Dot at last point
                const lastH = history[history.length - 1];
                const lastX = m.left + (history.length - 1) * stepX;
                const lastY = height - m.bottom - (s.getVal(lastH) / maxBps) * ph;
                ctx.beginPath();
                ctx.arc(lastX, lastY, 3, 0, Math.PI * 2);
                ctx.fillStyle = s.color;
                ctx.fill();
                ctx.strokeStyle = 'rgba(15,23,42,0.85)';
                ctx.lineWidth = 1.5;
                ctx.stroke();

                // Current value label at right edge
                ctx.fillStyle = s.color;
                ctx.font = "bold 10px monospace";
                ctx.textAlign = "left";
                ctx.fillText(formatChartRate(s.getVal(lastH)), width - m.right + 6, lastY + 3);
            });
        }

        // ── Packet Rate Distribution Chart ──
        function drawPacketRateChart(history) {
            const canvas = document.getElementById('ppsCanvas');
            if (!canvas || !history || history.length === 0) return;
            const ctx = canvas.getContext('2d');
            const dpr = window.devicePixelRatio || 1;
            const rect = canvas.getBoundingClientRect();
            canvas.width = rect.width * dpr;
            canvas.height = rect.height * dpr;
            ctx.scale(dpr, dpr);

            const lightT = document.documentElement.getAttribute('data-theme') === 'light';
            const gridClr = lightT ? 'rgba(15,23,42,0.10)' : 'rgba(255,255,255,0.05)';
            const axisClr = lightT ? 'rgba(15,23,42,0.6)' : 'rgba(248,250,252,0.45)';
            const axisClr2 = lightT ? 'rgba(15,23,42,0.5)' : 'rgba(248,250,252,0.35)';
            const zeroClr = lightT ? 'rgba(15,23,42,0.18)' : 'rgba(255,255,255,0.12)';

            const margin = ppsChartState.margin;
            const width = rect.width;
            const height = rect.height;
            const pw = width - margin.left - margin.right;
            const ph = height - margin.top - margin.bottom;
            const stepX = pw / Math.max(history.length - 1, 1);

            ctx.clearRect(0, 0, width, height);

            // Determine max PPS (per Tx/Rx total)
            let maxPPS = 1;
            history.forEach(h => {
                const txT = (h.tx_unicast || 0) + (h.tx_multicast || 0) + (h.tx_broadcast || 0);
                const rxT = (h.rx_unicast || 0) + (h.rx_multicast || 0) + (h.rx_broadcast || 0);
                if (txT > maxPPS) maxPPS = txT;
                if (rxT > maxPPS) maxPPS = rxT;
            });
            maxPPS = Math.max(maxPPS, 1);
            ppsChartState.maxVal = maxPPS;
            ppsChartState.stepX = stepX;
            ppsChartState.width = width;
            ppsChartState.height = height;
            ppsChartState.history = history;

            const numLabels = Math.min(6, history.length);

            // Grid
            ctx.strokeStyle = gridClr;
            ctx.lineWidth = 1;
            for (let i = 1; i <= 4; i++) {
                const gy = margin.top + (ph * i / 5);
                ctx.beginPath(); ctx.moveTo(margin.left, gy); ctx.lineTo(width - margin.right, gy); ctx.stroke();
            }

            // Y labels
            ctx.fillStyle = axisClr;
            ctx.font = "10px monospace";
            ctx.textAlign = "right";
            for (let i = 0; i <= 5; i++) {
                const v = Math.round((maxPPS * (5 - i)) / 5);
                const gy = margin.top + (ph * i / 5);
                ctx.fillText(formatPPS(v) + ' pps', margin.left - 8, gy + 3);
            }

            // X labels
            ctx.textAlign = "center";
            ctx.fillStyle = axisClr2;
            for (let i = 0; i < numLabels; i++) {
                const idx = Math.round((i * (history.length - 1)) / Math.max(numLabels - 1, 1));
                const x = margin.left + idx * stepX;
                const ts = history[idx].timestamp || '';
                ctx.fillText(ts.slice(3), x, height - margin.bottom + 14);
            }

            // Bar geometry: two stacked bars per time point (Tx left, Rx right)
            const barGroupW = stepX * 0.50;
            const barW = barGroupW * 0.42;
            const barGap = barGroupW * 0.16;
            const txColors = ['#a78bfa', '#fbbf24', '#fb7185'];
            const rxColors = ['#67e8f9', '#fcd34d', '#fda4af'];

            history.forEach((h, idx) => {
                const cx = margin.left + idx * stepX;
                const txVals = [h.tx_unicast || 0, h.tx_multicast || 0, h.tx_broadcast || 0];
                const rxVals = [h.rx_unicast || 0, h.rx_multicast || 0, h.rx_broadcast || 0];

                // Tx stack (left bar)
                let py = height - margin.bottom;
                txVals.forEach((v, vi) => {
                    if (v <= 0) return;
                    const hh = (v / maxPPS) * ph;
                    const barX = cx - barGroupW / 2 + barGap / 2;
                    ctx.fillStyle = txColors[vi];
                    ctx.fillRect(barX, py - hh, barW, hh);
                    py -= hh;
                });

                // Rx stack (right bar)
                py = height - margin.bottom;
                rxVals.forEach((v, vi) => {
                    if (v <= 0) return;
                    const hh = (v / maxPPS) * ph;
                    const barX = cx + barGap / 2;
                    ctx.fillStyle = rxColors[vi];
                    ctx.fillRect(barX, py - hh, barW, hh);
                    py -= hh;
                });
            });

            // Zero line
            ctx.strokeStyle = zeroClr;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(margin.left, height - margin.bottom);
            ctx.lineTo(width - margin.right, height - margin.bottom);
            ctx.stroke();
        }

        // Hover tooltip for bandwidth chart
        (function initBWTooltip() {
            const canvas = document.getElementById('bandwidthCanvas');
            const tip = document.getElementById('bwTooltip');
            if (!canvas || !tip) return;
            const parent = canvas.parentElement;

            canvas.addEventListener('mousemove', function(e) {
                const rect = canvas.getBoundingClientRect();
                const mx = e.clientX - rect.left;
                const my = e.clientY - rect.top;
                const m = bwChartState.margin;
                if (mx < m.left || mx > bwChartState.width - m.right) { tip.style.display = 'none'; return; }
                const idx = Math.round((mx - m.left) / bwChartState.stepX);
                const h = bwChartState.history[idx];
                if (!h) { tip.style.display = 'none'; return; }
                let html = `<div style="font-weight:bold;color:var(--text-secondary);margin-bottom:4px;">${h.timestamp || ''}</div>`;
                html += `<div style="color:var(--accent-cyan);">Tx B/s: <b>${formatChartRate(h.tx_speed || 0)}</b></div>`;
                html += `<div style="color:var(--success);">Rx B/s: <b>${formatChartRate(h.rx_speed || 0)}</b></div>`;
                tip.innerHTML = html;
                tip.style.display = 'block';
                let tx = e.clientX - parent.getBoundingClientRect().left + 14;
                let ty = e.clientY - parent.getBoundingClientRect().top - 10;
                if (tx + 180 > bwChartState.width) tx = e.clientX - parent.getBoundingClientRect().left - 180;
                if (ty < -20) ty = e.clientY - parent.getBoundingClientRect().top + 10;
                tip.style.left = tx + 'px';
                tip.style.top = ty + 'px';
            });

            canvas.addEventListener('mouseleave', function() {
                tip.style.display = 'none';
            });
        })();

        // Hover tooltip for packet rate chart
        (function initPPSTooltip() {
            const canvas = document.getElementById('ppsCanvas');
            const tip = document.getElementById('ppsTooltip');
            if (!canvas || !tip) return;
            const parent = canvas.parentElement;

            canvas.addEventListener('mousemove', function(e) {
                const rect = canvas.getBoundingClientRect();
                const mx = e.clientX - rect.left;
                const my = e.clientY - rect.top;
                const m = ppsChartState.margin;
                if (mx < m.left || mx > ppsChartState.width - m.right) { tip.style.display = 'none'; return; }
                const idx = Math.round((mx - m.left) / ppsChartState.stepX);
                const h = ppsChartState.history[idx];
                if (!h) { tip.style.display = 'none'; return; }
                let html = `<div style="font-weight:bold;color:var(--text-secondary);margin-bottom:4px;">${h.timestamp || ''}</div>`;
                html += `<div style="color:var(--accent-purple);">Tx: u=${h.tx_unicast || 0} m=${h.tx_multicast || 0} b=${h.tx_broadcast || 0} pps</div>`;
                html += `<div style="color:var(--accent-cyan);">Rx: u=${h.rx_unicast || 0} m=${h.rx_multicast || 0} b=${h.rx_broadcast || 0} pps</div>`;
                tip.innerHTML = html;
                tip.style.display = 'block';
                let tx = e.clientX - parent.getBoundingClientRect().left + 14;
                let ty = e.clientY - parent.getBoundingClientRect().top - 10;
                if (tx + 180 > ppsChartState.width) tx = e.clientX - parent.getBoundingClientRect().left - 180;
                if (ty < -20) ty = e.clientY - parent.getBoundingClientRect().top + 10;
                tip.style.left = tx + 'px';
                tip.style.top = ty + 'px';
            });

            canvas.addEventListener('mouseleave', function() {
                tip.style.display = 'none';
            });
        })();

        // Live Interactive Canvas Topology Renderer & Hover Engine
        let cachedPeers = [];
        let cachedRoutes = [];
        let transitRelaySet = new Set();
        let localNodeInfo = { name: "Local Node", ip: "10.0.0.1", ipv6: "fd00::1", peerID: "" };

        // Cache of multiaddr probe results, keyed by peer ID.
        //
        // Why: the popup's "Current Active Connected Pathway" header is sourced
        // from PeerInfoDTO.Addr (live libp2p connection). When no live conn
        // exists, that field is the sentinel string "unknown" — but the user
        // just probed and saw 18 reachable multiaddrs, so "unknown" reads as a
        // contradiction. The probe results have always been filled into the
        // popup DOM but never persisted, so reopening the popup drops them.
        //
        // Persisting them in a small Map lets the popup header grow a second
        // line ("Best Reachable Pathway") sourced from this cache, drawing an
        // honest distinction between "live connection" (Addr) and "best
        // reachable candidate from the last multiaddr probe".
        const multiaddrProbeCache = new Map(); // peerID -> { results: [], ts: number }
        const MULTIADDR_PROBE_TTL_MS = 5 * 60 * 1000; // 5 minutes

        const BOOTSTRAP_PALETTES = [
            { fill: "rgba(168, 85, 247, 0.88)", stroke: "#c084fc", glow: "rgba(168, 85, 247, 0.35)", text: "#e9d5ff" }, // Purple
            { fill: "rgba(217, 70, 239, 0.88)", stroke: "#f0abfc", glow: "rgba(217, 70, 239, 0.35)", text: "#f5d0fe" }, // Magenta
            { fill: "rgba(236, 72, 153, 0.88)", stroke: "#f472b6", glow: "rgba(236, 72, 153, 0.35)", text: "#fbcfe8" }, // Pink
            { fill: "rgba(139, 92, 246, 0.88)", stroke: "#a78bfa", glow: "rgba(139, 92, 246, 0.35)", text: "#ddd6fe" }, // Violet
        ];

        const STATIC_PALETTES = [
            { fill: "rgba(6, 182, 212, 0.88)", stroke: "#38bdf8", glow: "rgba(6, 182, 212, 0.35)", text: "#cff4fc" },  // Cyan
            { fill: "rgba(20, 184, 166, 0.88)", stroke: "#2dd4bf", glow: "rgba(20, 184, 166, 0.35)", text: "#ccfbf1" }, // Teal
            { fill: "rgba(59, 130, 246, 0.88)", stroke: "#60a5fa", glow: "rgba(59, 130, 246, 0.35)", text: "#dbeafe" }, // Sky Blue
        ];

        const PEER_PALETTES = [
            { fill: "rgba(16, 185, 129, 0.88)", stroke: "#34d399", glow: "rgba(16, 185, 129, 0.35)", text: "#d1fae5" }, // Emerald
            { fill: "rgba(245, 158, 11, 0.88)", stroke: "#fbbf24", glow: "rgba(245, 158, 11, 0.35)", text: "#fef3c7" }, // Amber
            { fill: "rgba(249, 115, 22, 0.88)", stroke: "#fb923c", glow: "rgba(249, 115, 22, 0.35)", text: "#ffedd5" }, // Orange
            { fill: "rgba(132, 204, 22, 0.88)", stroke: "#a3e635", glow: "rgba(132, 204, 22, 0.35)", text: "#ecfccb" }, // Lime
            { fill: "rgba(99, 102, 241, 0.88)", stroke: "#818cf8", glow: "rgba(99, 102, 241, 0.35)", text: "#e0e7ff" }, // Indigo
            { fill: "rgba(244, 63, 94, 0.88)",  stroke: "#fb7185", glow: "rgba(244, 63, 94, 0.35)",  text: "#ffe4e6" }, // Rose
        ];

        function isPeerRelayed(peer) {
            if (!peer) return false;
            if (peer.is_relayed !== undefined) {
                return peer.is_relayed;
            }
            const trans = peer.transport || '';
            if (trans === 'Circuit Relay' || trans === 'Overlay Relay') return true;
            const addr = peer.addr || peer.address || '';
            return addr.includes('/p2p-circuit');
        }

        // encBadge renders a per-peer encryption/obfuscation status chip for the
        // peers table. p.obf_algo is one of: "none" (no negotiation / plaintext),
        // "aes-gcm", "chacha20".
        function encBadge(p) {
            const algo = (p && p.obf_algo) || 'none';
            if (algo === 'none') {
                return '<span class="pill-badge" style="font-size:0.7rem; padding:2px 8px; background:var(--border-subtle); border-color:var(--border-subtle); color:var(--text-secondary);" title="No encryption negotiation / plaintext obfuscation">○ Plaintext</span>';
            }
            const color = algo === 'chacha20' ? '#a78bfa' : '#34d399';
            return `<span class="pill-badge" style="font-size:0.7rem; padding:2px 8px; background:var(--accent-green-fill); border-color:var(--accent-green-border); color:${color};" title="AEAD encryption active: ${algo}">🔒 ${algo}</span>`;
        }

        // handshakeBadge renders the measured SeqSync handshake convergence latency:
        // time from first crypto handshake attempt to the link becoming usable.
        // 0 / unknown means not yet measured. High values under relay/NAT indicate a
        // flaky crypto handshake for this peer.
        function handshakeBadge(p) {
            const ms = (p && typeof p.seqsync_converge_ms === 'number') ? p.seqsync_converge_ms : 0;
            if (ms === 0) {
                return '<span style="font-size:0.68rem; color:var(--text-muted);" title="Handshake convergence time not yet measured">⌛ —</span>';
            }
            const secs = ms / 1000;
            const txt = secs >= 1 ? secs.toFixed(1) + 's' : ms + 'ms';
            const color = ms < 1000 ? '#94a3b8' : (ms < 5000 ? '#fbbf24' : '#f87171');
            return `<span style="font-size:0.68rem; color:${color};" title="SeqSync handshake convergence: ${ms} ms (time from first crypto handshake to link usable)">⌛ ${txt}</span>`;
        }

        // connStateBadge renders a compact stage-progress indicator for a peer's
        // overall connectivity: connection → app protocol → encryption → data.
        // p.conn_state is the aggregate verdict; p.conn_stage (0..4) drives the
        // progress dots; p.conn_detail is the hover/secondary text.
        const CONN_STATE_META = {
            ok:            { color: '#34d399', bg: 'rgba(52,211,153,0.12)',  bd: 'rgba(52,211,153,0.35)' },
            relay_ok:      { color: '#fbbf24', bg: 'rgba(245,158,11,0.12)',  bd: 'rgba(245,158,11,0.35)' },
            connecting:    { color: '#38bdf8', bg: 'rgba(56,189,248,0.12)',  bd: 'rgba(56,189,248,0.35)' },
            proto_mismatch:{ color: '#f87171', bg: 'rgba(248,113,113,0.12)', bd: 'rgba(248,113,113,0.35)' },
            obf_failed:    { color: '#f87171', bg: 'rgba(248,113,113,0.12)', bd: 'rgba(248,113,113,0.35)' },
            unreachable:   { color: '#94a3b8', bg: 'rgba(148,163,184,0.12)', bd: 'rgba(148,163,184,0.35)' },
        };
        const CONN_STAGE_LABELS = ['Conn', 'Proto', 'Crypt', 'Data'];
        function connStateBadge(p) {
            const st = (p && p.conn_state) || 'connecting';
            const stage = (p && typeof p.conn_stage === 'number') ? p.conn_stage : 0;
            const meta = CONN_STATE_META[st] || CONN_STATE_META.connecting;
            const label = t('conn_' + st);
            const detail = (p && p.conn_detail) ? p.conn_detail : '';
            // Stage dots: stage count = completed stages (1 conn,2 proto,3 crypt,4 data).
            let dots = '';
            for (let i = 0; i < CONN_STAGE_LABELS.length; i++) {
                const on = i < stage;
                const c = on ? meta.color : 'rgba(148,163,184,0.4)';
                dots += `<span style="display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:2px; background:${c};" title="${CONN_STAGE_LABELS[i]}"></span>`;
            }
            return `<div style="display:flex; flex-direction:column; gap:3px;">
                <span class="pill-badge" style="font-size:0.68rem; padding:2px 7px; background:${meta.bg}; border-color:${meta.bd}; color:${meta.color}; white-space:nowrap;" title="${escapeHTML(detail)}">${label}</span>
                <div style="display:flex; align-items:center;">${dots}</div>
            </div>`;
        }

        // returnPathBadge renders the asymmetric-routing return-path liveness for
        // a peer — deliberately independent of the outbound ConnState verdict. It
        // uses CSS classes (.rp-ok / .rp-dead / .rp-idle) wired in styles.css so
        // the colours follow the active theme's CSS variables (no hardcoded rgba
        // in the markup). The hover title carries the precise detail string.
        function returnPathBadge(p) {
            const st = (p && p.return_path) || 'idle';
            const detail = (p && p.return_path_detail) || '';
            const label = t('return_' + st);
            return `<span class="pill-badge rp-badge rp-${st}" title="${escapeHTML(detail)}">${escapeHTML(label)}</span>`;
        }

        function getNodeColor(peer) {
            let hash = 0;
            const str = peer.peer_id || peer.node_name || "peer";
            for (let i = 0; i < str.length; i++) {
                hash = (hash * 31 + str.charCodeAt(i)) >>> 0;
            }

            if (isPeerRelayed(peer)) {
                return { fill: "rgba(245, 158, 11, 0.88)", stroke: "#fbbf24", glow: "rgba(245, 158, 11, 0.45)", text: "#fef3c7" };
            } else if (peer.role === 'Bootstrap') {
                return BOOTSTRAP_PALETTES[hash % BOOTSTRAP_PALETTES.length];
            } else if (peer.role === 'Static') {
                return STATIC_PALETTES[hash % STATIC_PALETTES.length];
            } else {
                return PEER_PALETTES[hash % PEER_PALETTES.length];
            }
        }

        /* ── Protocol Streams & Channels Monitor ───────────────────────── */
        const channelCategoryConfig = {
            sync:         { icon: '🔄', color: '#38bdf8', borderColor: 'var(--accent-cyan-border)' },
            routing:      { icon: '🗺️', color: '#a78bfa', borderColor: 'var(--accent-purple-border)' },
            pubsub:       { icon: '📡', color: '#fbbf24', borderColor: 'var(--accent-yellow-border, #92400e)' },
            data:         { icon: '🚀', color: '#34d399', borderColor: 'var(--accent-green-border)' },
            security:     { icon: '🛡️', color: '#f87171', borderColor: 'var(--danger-border, #7f1d1d)' },
            transport:    { icon: '🕳️', color: '#c084fc', borderColor: 'var(--accent-purple-border)' },
            diagnostics:  { icon: '🩺', color: '#94a3b8', borderColor: 'var(--border-subtle)' },
            discovery:    { icon: '🔍', color: '#38bdf8', borderColor: 'var(--accent-cyan-border)' },
        };

        function channelStatusBadge(status) {
            if (status === 'active')    return `<span style="color:#34d399;font-weight:700;font-size:0.75rem;">● ${t('channel_status_active') || 'Active'}</span>`;
            if (status === 'running')   return `<span style="color:#38bdf8;font-weight:700;font-size:0.75rem;">● ${t('channel_status_running') || 'Running'}</span>`;
            if (status === 'idle')      return `<span style="color:#94a3b8;font-weight:700;font-size:0.75rem;">◌ ${t('channel_status_idle') || 'Idle'}</span>`;
            if (status === 'standby')   return `<span style="color:#fbbf24;font-weight:700;font-size:0.75rem;">⏸ ${t('channel_status_standby') || 'Standby'}</span>`;
            if (status === 'ready')     return `<span style="color:#a78bfa;font-weight:700;font-size:0.75rem;">● ${t('channel_status_ready') || 'Ready'}</span>`;
            if (status === 'open-mode') return `<span style="color:#fbbf24;font-weight:700;font-size:0.75rem;">◌ ${t('channel_status_open') || 'Open'}</span>`;
            return `<span style="color:var(--text-muted);font-size:0.75rem;">◌ ${escapeHTML(status)}</span>`;
        }

        function renderProtocolChannels(data) {
            const channels = data.protocol_channels || [];
            const streams  = data.active_streams  || [];

            // Update stream count badge
            const badge = document.getElementById('activeStreamsBadge');
            if (badge) badge.textContent = `${streams.length} ${t('lbl_active_streams') || 'Streams'}`;

            // --- Channels Grid ---
            const grid = document.getElementById('protoChannelsGrid');
            if (grid) {
                if (channels.length === 0) {
                    grid.innerHTML = `<div class="empty-row" style="padding:16px;color:var(--text-muted);">${t('no_channels') || 'No active protocol channels'}</div>`;
                } else {
                    grid.innerHTML = channels.map(ch => {
                        const cfg = channelCategoryConfig[ch.category] || channelCategoryConfig.diagnostics;
                        const totalStreams = ch.active_streams || 0;
                        const inStr  = ch.inbound_streams  || 0;
                        const outStr = ch.outbound_streams || 0;
                        const normId = (ch.id || '').replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
                        const rawKey = 'channel_' + ch.id + '_name';
                        const normKey = 'channel_' + normId + '_name';
                        const dict = i18nDict[currentLang] || i18nDict.en || {};
                        const enDict = i18nDict.en || {};
                        const chName = dict[rawKey] || dict[normKey] || enDict[rawKey] || enDict[normKey] || ch.name || ch.id;
                        const catName = t('category_' + ch.category) || ch.category;

                        let detailsStr = ch.details || '';
                        if (normId === 'seqsync') {
                            detailsStr = `Streams: ${totalStreams} (↓${inStr} ↑${outStr}) · ${t('channel_seqsync_desc') || 'Window Dedup & Replay Protection'}`;
                        } else if (normId === 'lsa') {
                            detailsStr = `Streams: ${totalStreams} (↓${inStr} ↑${outStr}) · ${t('channel_lsa_desc') || 'Dijkstra Shortest Path'}`;
                        } else if (normId === 'peekmap' || normId === 'peek-map') {
                            detailsStr = `Streams: ${totalStreams} (↓${inStr} ↑${outStr}) · ${t('channel_peekmap_desc') || t('channel_peek-map_desc') || 'Bootstrap Topology Sync'}`;
                        } else if (normId === 'data') {
                            const cipher = (data.obfs_algo || 'auto');
                            const mode = (data.obfs_mode || 'fixed');
                            detailsStr = `${t('channel_data_proto') || 'Layer-2 Ethernet Overlay'} · ${t('cipher_lbl') || 'Cipher'}: ${cipher} · Mode: ${mode}`;
                        } else if (normId === 'auth') {
                            detailsStr = `${t('channel_auth_desc') || 'PSK Mesh Network Isolation'} · Streams: ${totalStreams}`;
                        } else if (normId === 'dcutr') {
                            detailsStr = `${t('channel_dcutr_desc') || 'Direct Connection Upgrade'} · Streams: ${totalStreams}`;
                        }


                        return `
                            <div class="glass-card ext61" style="border-left:3px solid ${cfg.color}; display:flex; flex-direction:column; gap:6px; padding:14px 16px;">
                                <div style="display:flex; align-items:center; justify-content:space-between; gap:6px;">
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <span style="font-size:1.2rem;">${cfg.icon}</span>
                                        <strong style="color:var(--text-primary); font-size:0.9rem;">${escapeHTML(chName)}</strong>
                                    </div>
                                    ${channelStatusBadge(ch.status)}
                                </div>
                                <div style="font-family:monospace; font-size:0.72rem; color:var(--text-muted); word-break:break-all;">${escapeHTML(ch.protocol)}</div>
                                <div style="display:flex; gap:10px; font-size:0.78rem; color:var(--text-secondary);">
                                    <span>↓ ${inStr}  ↑ ${outStr}  ∑ ${totalStreams}</span>
                                    <span style="margin-left:auto; background:var(--glass-fill); padding:1px 7px; border-radius:5px; font-size:0.7rem; color:${cfg.color};">${escapeHTML(catName)}</span>
                                </div>
                                ${detailsStr ? `<div style="font-size:0.75rem; color:var(--text-dim); margin-top:2px;">${escapeHTML(detailsStr)}</div>` : ''}
                            </div>
                        `;
                    }).join('');
                }
            }


            // --- Streams Table ---
            const query = (document.getElementById('streamSearchInput') || {}).value || '';
            const q = query.toLowerCase();
            const filtered = q
                ? streams.filter(s =>
                    (s.protocol      && s.protocol.toLowerCase().includes(q)) ||
                    (s.protocol_name && s.protocol_name.toLowerCase().includes(q)) ||
                    (s.peer_id       && s.peer_id.toLowerCase().includes(q)) ||
                    (s.peer_id_short && s.peer_id_short.toLowerCase().includes(q)) ||
                    (s.peer_name     && s.peer_name.toLowerCase().includes(q)) ||
                    (s.transport     && s.transport.toLowerCase().includes(q)) ||
                    (s.remote_addr   && s.remote_addr.toLowerCase().includes(q))
                  )
                : streams;

            const tbody = document.getElementById('streamsTableBody');
            if (filtered.length === 0) {
                const emptyHtml = `<tr><td colspan="5" class="empty-row" style="text-align:center;padding:20px;color:var(--text-muted);">${t('no_matching_streams') || 'No active protocol streams found'}</td></tr>`;
                if (tbody._lastHtml !== emptyHtml) {
                    tbody._lastHtml = emptyHtml;
                    tbody.innerHTML = emptyHtml;
                }
                return;
            }

            const newHtml = filtered.map(s => {
                const dirLabel = s.direction === 'outbound'
                    ? `<span style="color:#38bdf8;">${t('dir_out') || 'Outbound ↑'}</span>`
                    : `<span style="color:#a78bfa;">${t('dir_in') || 'Inbound ↓'}</span>`;
                const transportBadge = `<span style="background:var(--glass-fill);border:1px solid var(--border-subtle);padding:2px 7px;border-radius:5px;font-size:0.73rem;color:var(--text-secondary);">${escapeHTML(s.transport || 'P2P')}</span>`;
                const statusDot = `<span style="color:#34d399;font-weight:700;font-size:0.75rem;">● ${t('stream_active') || 'Active'}</span>`;
                const peerDisplay = s.peer_name
                    ? `<div style="font-weight:600;color:var(--text-primary);font-size:0.85rem;">${escapeHTML(s.peer_name)}</div><div style="font-family:monospace;font-size:0.72rem;color:var(--text-muted);">${escapeHTML(s.peer_id_short || s.peer_id)}</div>`
                    : `<div style="font-family:monospace;font-size:0.75rem;color:var(--text-muted);">${escapeHTML(s.peer_id_short || s.peer_id)}</div>`;
                return `
                    <tr style="border-bottom:1px solid var(--border-subtle);">
                        <td style="padding:8px 12px;">
                            <div style="font-weight:600;color:var(--text-primary);font-size:0.84rem;">${escapeHTML(s.protocol_name || s.protocol)}</div>
                            <div style="font-family:monospace;font-size:0.7rem;color:var(--text-muted);">${escapeHTML(s.protocol)}</div>
                        </td>
                        <td style="padding:8px 12px;">${peerDisplay}</td>
                        <td style="padding:8px 12px;">${dirLabel}</td>
                        <td style="padding:8px 12px;">
                            <div style="display:flex;flex-direction:column;gap:3px;">
                                ${transportBadge}
                                <div style="font-family:monospace;font-size:0.68rem;color:var(--text-dim);word-break:break-all;">${escapeHTML(s.remote_addr || '')}</div>
                            </div>
                        </td>
                        <td style="padding:8px 12px;">${statusDot}</td>
                    </tr>
                `;
            }).join('');

            if (tbody._lastHtml !== newHtml) {
                tbody._lastHtml = newHtml;
                tbody.innerHTML = newHtml;
            }
        }


        function renderExitStatus(data) {
            const panel = document.getElementById('exitStatusPanel');
            const body = document.getElementById('exitStatusBody');
            if (!panel || !body) return;
            const exit = (data && data.exit_node) || {};
            const role = exit.role || '';
            if (!role) {
                body.innerHTML = `<span style="color:var(--text-muted);">● ${t('exit_status_inactive') || 'No Exit Node tunnel active'}</span>`;
                return;
            }
            const roleLabel = role === 'client'
                ? (t('exit_status_role_client') || 'Client')
                : role === 'server'
                    ? (t('exit_status_role_server') || 'Server (offering egress)')
                    : (t('exit_status_role_both') || 'Client + Server');
            const roleColor = role === 'client' ? '#38bdf8' : role === 'server' ? '#34d399' : '#a78bfa';

            let html = `<div style="margin-bottom:6px;"><span style="color:${roleColor}; font-weight:700;">● ${roleLabel}</span></div>`;

            if (exit.active && exit.active_peer_id) {
                const name = exit.active_exit_peer_name || exit.active_peer_id.substring(0, 12) + '…';
                const tap = exit.active_exit_tap_ip || exit.active_exit_ip || '—';
                html += `<div style="display:flex; flex-direction:column; gap:3px;">
                    <div><span style="color:var(--text-muted);">${t('exit_status_routing_via') || 'Routing traffic through'}:</span>
                        <span style="color:var(--text-primary); font-weight:600;"> ${escapeHTML(name)}</span></div>
                    <div style="font-size:0.74rem; color:var(--text-secondary);">
                        <span>${t('exit_status_peer') || 'Peer'}:</span> <code style="color:var(--info);">${escapeHTML(exit.active_peer_id)}</code>
                        &nbsp;·&nbsp; <span>${t('exit_status_tap_ip') || 'TAP IP'}:</span> <code style="color:var(--info);">${escapeHTML(tap)}</code>
                    </div>`;
                if (exit.active_exit_tap_ipv6) {
                    html += `<div style="font-size:0.74rem; color:var(--text-secondary);">
                        <span>${t('exit_status_tap_ipv6') || 'TAP IPv6'}:</span> <code style="color:var(--accent-purple);">${escapeHTML(exit.active_exit_tap_ipv6)}</code>
                    </div>`;
                }
                html += `</div>`;
            } else if (exit.enable) {
                html += `<div style="color:var(--text-muted); font-size:0.76rem;">${t('exit_status_offering') || 'Offering egress to the mesh'}${exit.wan_interface ? ' · WAN: ' + escapeHTML(exit.wan_interface) : ''}${exit.nat_masquerade ? ' · NAT' : ''}</div>`;
            }
            body.innerHTML = html;
        }

        function renderExitClientCard(data) {
            const body = document.getElementById('exitClientCardBody');
            const badge = document.getElementById('exitClientBadge');
            if (!body || !badge) return;

            const exit = (data && data.exit_node) || {};
            const isClientActive = exit.active && exit.active_peer_id;

            // The Exit Gateway search input + pagination bar only make sense when
            // we're actually rendering the candidate grid (no active session).
            // Hide both while a session is up so the operator doesn't see a
            // confusing "无匹配" against the active-session banner.
            const exitSearchEl = document.getElementById('exitClientSearch');
            const exitBarEl = document.getElementById('pg-exitClientCardBody');
            if (exitSearchEl) exitSearchEl.style.display = isClientActive ? 'none' : '';
            if (exitBarEl) exitBarEl.style.display = isClientActive ? 'none' : '';

            if (isClientActive) {
                badge.innerText = "⚡ Active";
                badge.className = "pill-badge role-static";
                badge.style.background = "rgba(16,185,129,0.2)";
                badge.style.color = "#a7f3d0";
                badge.style.border = "1px solid rgba(16,185,129,0.4)";

                const name = exit.active_exit_peer_name || exit.active_peer_id.substring(0, 12) + '…';
                const tapIP = exit.active_exit_tap_ip || exit.active_exit_ip || '—';

                body.innerHTML = `
                    <div class="exit-active-banner">
                        <div class="exit-active-info">
                            <div class="exit-active-title">
                                <span class="exit-active-bolt">⚡</span>
                                <span>${t('exit_client_status_active') || 'Routing all internet traffic via Exit Node'}</span>
                            </div>
                            <div class="exit-active-meta">
                                ${t('exit_status_peer') || 'Gateway'}: <strong>${escapeHTML(name)}</strong>
                                (<code>${escapeHTML(tapIP)}</code>)
                            </div>
                        </div>
                        <button class="exit-disconnect-btn" data-onclick="disconnectExitGateway()">
                            ${t('btn_disconnect_exit') || '⏹️ Disconnect Exit'}
                        </button>
                    </div>
                `;
            } else {
                badge.innerText = "Inactive";
                badge.className = "pill-badge role-peer";
                badge.style.background = "";
                badge.style.color = "";
                badge.style.border = "";

                // Only peers that have explicitly enabled Exit Node gateway mode on
                // their own side can be chosen as our outbound gateway — peers
                // without `is_exit_node=true` simply do not offer egress, so
                // listing them as selectable candidates misleads the operator
                // into believing they can route through a peer that won't
                // actually forward traffic. Filter accordingly.
                const candidatePeers = (data.active_peers || []).filter(p => p.tap_ip && p.is_exit_node);

                if (candidatePeers.length === 0) {
                    body.innerHTML = `
                        <div class="exit-status-info">
                            <span class="exit-status-ico">📡</span>
                            <span>${t('exit_client_status_inactive') || 'No Exit Gateway active (using local default gateway)'}</span>
                        </div>
                        <div class="exit-candidates-empty" style="text-align:center; padding:14px 4px;">
                            ${t('exit_client_no_peers') || 'No online peers currently available'}
                        </div>
                    `;
                    return;
                }

                // Build candidate cards (peer picker grid). Selected state is preserved across
                // fetchStats() re-renders by reading the last-chosen peer ID from a dataset on `body`.
                const previouslySelected = body.dataset.selectedPeerId || '';
                // If the previously selected peer is no longer in the candidate list, drop it.
                const stillExists = candidatePeers.some(p => p.peer_id === previouslySelected);
                const selectedId = stillExists ? previouslySelected : '';
                body.dataset.selectedPeerId = selectedId;

                const cards = candidatePeers.map(p => {
                    const name = p.node_name || p.peer_id.substring(0, 12) + '…';
                    const isExitServer = !!p.is_exit_node;
                    const icon = isExitServer ? '🚀' : '🌐';
                    const nameLabel = isExitServer ? `${name} · ${t('topo_badge_exit_server') || 'Exit Server'}` : name;
                    const v4 = (p.tap_ip || '').trim();
                    const v6 = (p.tap_ipv6 || '').trim();
                    const rtt = (p.rtt_ms != null && p.rtt_ms !== '') ? Number(p.rtt_ms) : null;
                    // RTT pill sits in the top-right of the card, color-coded by latency.
                    let rttPill = '';
                    if (rtt != null) {
                        const rttCls = rtt < 80 ? '' : (rtt < 200 ? ' rtt-warn' : ' rtt-err');
                        rttPill = `<span class="exit-peer-rtt${rttCls}" title="Round-trip time">⏱ ${rtt} ms</span>`;
                    }
                    const metaRows = [];
                    if (v4) {
                        metaRows.push(
                            `<div class="exit-peer-meta-row exit-peer-meta-ipv4">` +
                                `<span class="ip" title="${escapeHTML(v4)}">${escapeHTML(v4)}</span>` +
                            `</div>`
                        );
                    }
                    if (v6) {
                        metaRows.push(
                            `<div class="exit-peer-meta-row exit-peer-meta-ipv6">` +
                                `<span class="ip" title="${escapeHTML(v6)}">${escapeHTML(v6)}</span>` +
                            `</div>`
                        );
                    }
                    const meta = metaRows.join('') ||
                        `<div class="exit-peer-meta-row"><span class="ip ip-empty">—</span></div>`;
                    const isSelected = p.peer_id === selectedId;
                    return `
                        <button type="button" class="exit-peer-card${isSelected ? ' selected' : ''}" data-peer-id="${escapeHTML(p.peer_id)}" data-tap-ip="${escapeHTML(p.tap_ip || '')}" data-tap-ipv6="${escapeHTML(p.tap_ipv6 || '')}" aria-pressed="${isSelected}">
                            <div class="exit-peer-icon">${icon}</div>
                            <div class="exit-peer-info">
                                <div class="exit-peer-info-head">
                                    <span class="exit-peer-name">${escapeHTML(nameLabel)}</span>
                                    ${rttPill}
                                </div>
                                <div class="exit-peer-meta">${meta}</div>
                            </div>
                        </button>
                    `;
                }).join('');

                body.innerHTML = `
                    <div class="exit-status-info">
                        <span class="exit-status-ico">📡</span>
                        <span>${t('exit_client_status_inactive') || 'No Exit Gateway active (using local default gateway)'}</span>
                    </div>
                    <div class="exit-candidates-grid">${cards}</div>
                    <div class="exit-action-bar">
                        <span class="exit-hint" id="exitPickerHint">${t('exit_picker_hint') || 'Select a peer above to route traffic through'}</span>
                        <button class="exit-connect-btn" id="exitConnectBtn" ${selectedId ? '' : 'disabled'}>
                            ${t('btn_connect_exit') || '🚀 Activate Exit Gateway'}
                        </button>
                    </div>
                `;

                // Wire up click handlers (after innerHTML replaces DOM nodes).
                body.querySelectorAll('.exit-peer-card').forEach(card => {
                    card.addEventListener('click', () => {
                        const peerId = card.getAttribute('data-peer-id');
                        const wasSelected = card.classList.contains('selected');
                        body.querySelectorAll('.exit-peer-card').forEach(c => {
                            c.classList.remove('selected');
                            c.setAttribute('aria-pressed', 'false');
                        });
                        if (!wasSelected) {
                            card.classList.add('selected');
                            card.setAttribute('aria-pressed', 'true');
                            body.dataset.selectedPeerId = peerId;
                        } else {
                            body.dataset.selectedPeerId = '';
                        }
                        const btn = document.getElementById('exitConnectBtn');
                        if (btn) btn.disabled = !body.dataset.selectedPeerId;
                    });
                });

                const connectBtn = document.getElementById('exitConnectBtn');
                if (connectBtn) {
                    connectBtn.addEventListener('click', connectSelectedExitGatewayFromCard);
                }
            }
        }

        window.connectSelectedExitGatewayFromCard = function() {
            const body = document.getElementById('exitClientCardBody');
            if (!body) return;
            const peerID = body.dataset.selectedPeerId || '';
            const card = body.querySelector('.exit-peer-card.selected');
            const tapIP = card ? (card.getAttribute('data-tap-ip') || '') : '';
            const tapIPv6 = card ? (card.getAttribute('data-tap-ipv6') || '') : '';
            if (!peerID) return;
            togglePeerAsExitGateway(peerID, tapIP, tapIPv6);
        };

        window.disconnectExitGateway = function() {
            const btn = document.querySelector('#exitClientCardBody .exit-disconnect-btn');
            if (btn && btn.classList.contains('loading')) return;
            if (btn) {
                btn.classList.add('loading');
                btn.disabled = true;
                btn.textContent = t('btn_disconnecting') || 'Disconnecting...';
            }
            fetch('/api/exitnode', withAuth({
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'clear', peer_id: '', exit_tap_ip: '' })
            })).then(res => {
                if (res.ok) {
                    showToast(t('exit_disconnected') || 'Exit Gateway disconnected');
                } else {
                    return res.json().then(err => { throw new Error(err.error || 'Operation failed'); }).catch(() => { throw new Error('Operation failed'); });
                }
            }).catch(e => {
                showToast('❌ ' + e.message, true);
                if (btn) { btn.classList.remove('loading'); btn.disabled = false; btn.textContent = t('btn_disconnect_exit') || '⏹️ Disconnect Exit'; }
            }).finally(() => {
                setTimeout(() => fetchStats(), 800);
            });
        };

        // ----- ACL status card renderer (driven by /api/stats -> data.acl) -----
        // Replaces the previous hardcoded "Open Mesh" stub with live counters
        // (accepted / dropped / per-rule hits / recent drops). The card is
        // refreshed on every fetchStats tick so the user sees firewall
        // activity in real time.
        function renderACLCard(data) {
            const body = document.getElementById('aclRulesSummary');
            const badge = document.getElementById('aclStatusBadge');
            if (!body || !badge) return;

            const acl = (data && data.acl) || {};
            const enabled = !!acl.enabled;
            const ruleCount = acl.rule_count || 0;
            const defaultAct = (acl.default_action || 'allow').toLowerCase();
            const accepted = acl.accepted || 0;
            const dropped = acl.dropped || 0;
            const ruleHits = acl.rule_hits || [];
            const recentDrops = acl.recent_drops || [];
            const uptimeSec = acl.uptime_sec || 0;

            // Badge
            if (!enabled) {
                badge.innerText = t('acl_badge_open') || 'Open Mesh';
                badge.className = 'pill-badge role-peer';
                badge.style.background = '';
                badge.style.color = '';
                badge.style.border = '';
            } else {
                badge.innerText = t('acl_badge_active') || '● Active';
                badge.className = 'pill-badge role-static';
                badge.style.background = 'rgba(167,139,250,0.2)';
                badge.style.color = '#c4b5fd';
                badge.style.border = '1px solid rgba(167,139,250,0.4)';
            }

            // Body
            const total = accepted + dropped;
            const acceptPct = total > 0 ? ((accepted / total) * 100).toFixed(1) : '—';
            const dropPct = total > 0 ? ((dropped / total) * 100).toFixed(1) : '—';
            const uptimeStr = formatUptime(uptimeSec);

            const defActBadge = defaultAct === 'drop' || defaultAct === 'deny'
                ? `<span style="color:var(--danger); background:var(--danger-fill); padding:1px 7px; border-radius:4px; font-weight:600; font-size:0.72rem; border:1px solid var(--danger-fill);">${(t('acl_default_drop') || 'DROP (deny)').toUpperCase()}</span>`
                : `<span style="color:var(--success); background:var(--accent-green-fill); padding:1px 7px; border-radius:4px; font-weight:600; font-size:0.72rem; border:1px solid var(--accent-green-fill);">${(t('acl_default_accept') || 'ACCEPT (allow)').toUpperCase()}</span>`;

            let html = '';

            if (!enabled) {
                html += `<div style="color:var(--text-secondary); font-size:0.78rem; line-height:1.5;">
                    ${t('acl_open_desc') || 'Mesh Firewall is Open (All P2P Traffic Allowed)'}<br>
                    <span style="color:var(--text-muted); font-size:0.72rem;">${t('acl_open_hint') || 'Enable ACL in Settings → ACL Editor to enforce rules.'}</span>
                </div>`;
            } else {
                // Status row
                html += `<div style="display:flex; align-items:center; flex-wrap:wrap; gap:6px; font-size:0.78rem; color:var(--text-dim);">
                    <span style="color:var(--text-secondary);">${t('acl_label_rules') || 'Rules'}:</span>
                    <strong style="color:var(--text-primary);">${ruleCount}</strong>
                    <span style="color:var(--text-muted);">·</span>
                    <span style="color:var(--text-secondary);">${t('acl_label_default') || 'Default'}:</span>
                    ${defActBadge}
                </div>`;

                // Live counters
                html += `<div style="background:var(--surface-fill); border:1px solid var(--glass-fill); border-radius:6px; padding:8px 10px; display:grid; grid-template-columns: 1fr 1fr; gap:6px;">
                    <div>
                        <div style="color:var(--text-muted); font-size:0.68rem; text-transform:uppercase; letter-spacing:0.5px;">${t('acl_label_accepted') || 'Accepted'}</div>
                        <div style="color:var(--success); font-weight:700; font-size:1.05rem; line-height:1.2;">${formatNum(accepted)}</div>
                        <div style="color:var(--text-muted); font-size:0.68rem;">${acceptPct}%</div>
                    </div>
                    <div>
                        <div style="color:var(--text-muted); font-size:0.68rem; text-transform:uppercase; letter-spacing:0.5px;">${t('acl_label_dropped') || 'Dropped'}</div>
                        <div style="color:${dropped > 0 ? 'var(--danger)' : 'var(--success)'}; font-weight:700; font-size:1.05rem; line-height:1.2;">${formatNum(dropped)}</div>
                        <div style="color:var(--text-muted); font-size:0.68rem;">${dropPct}%</div>
                    </div>
                </div>`;
                html += `<div style="color:var(--text-muted); font-size:0.68rem;">${t('acl_label_uptime') || 'Uptime'}: ${uptimeStr}</div>`;

                // Top matched rules (max 3)
                if (ruleHits.length > 0) {
                    html += `<div style="margin-top:2px;">`;
                    html += `<div style="color:var(--text-secondary); font-size:0.72rem; margin-bottom:4px;">${t('acl_label_top_rules') || 'Top matched rules'}:</div>`;
                    const top = ruleHits.slice(0, 3);
                    html += top.map(h => {
                        const isAccept = h.hits > 0; // cosmetic — actual action shown in detail
                        return `<div style="display:flex; justify-content:space-between; align-items:center; font-size:0.74rem; padding:3px 6px; background:var(--glass-fill); border-radius:4px; border:1px solid var(--glass-fill);">
                            <span><span style="color:var(--accent-purple); font-family:var(--font-mono, monospace); font-weight:600;">#${escapeHTML(h.rule_id)}</span></span>
                            <span style="color:var(--success); font-weight:600;">${formatNum(h.hits)} ${t('acl_label_hits') || 'hits'}</span>
                        </div>`;
                    }).join('');
                    if (ruleHits.length > 3) {
                        html += `<div style="color:var(--text-muted); font-size:0.7rem; text-align:center; margin-top:3px;">+${ruleHits.length - 3} ${t('acl_label_more') || 'more'}</div>`;
                    }
                    html += `</div>`;
                }

                // Recent drops (max 3, only when there ARE drops)
                if (recentDrops.length > 0) {
                    html += `<div style="margin-top:4px;">`;
                    html += `<div style="color:var(--text-secondary); font-size:0.72rem; margin-bottom:4px;">${t('acl_label_recent_drops') || 'Recent drops'}:</div>`;
                    const recent = recentDrops.slice(-3).reverse();
                    html += recent.map(d => {
                        const timeStr = new Date(d.time).toLocaleTimeString();
                        const ruleLbl = d.rule_id ? `#${escapeHTML(d.rule_id)}` : (t('acl_label_default_action') || 'default');
                        return `<div style="font-size:0.7rem; padding:3px 6px; background:var(--danger-fill); border-left:2px solid var(--danger); border-radius:3px; color:var(--danger); font-family:var(--font-mono, monospace);">
                            <span style="color:var(--text-secondary);">${timeStr}</span> · ${escapeHTML((d.peer_id || '?').substring(0, 12))}… · ${ruleLbl}
                        </div>`;
                    }).join('');
                    html += `</div>`;
                }
            }

            body.innerHTML = html;
        }

        function formatNum(n) {
            if (typeof n !== 'number') n = Number(n) || 0;
            if (n < 1000) return String(n);
            if (n < 1000000) return (n / 1000).toFixed(n < 10000 ? 1 : 0) + 'K';
            return (n / 1000000).toFixed(1) + 'M';
        }

        function formatUptime(sec) {
            sec = Number(sec) || 0;
            if (sec < 60) return sec + 's';
            if (sec < 3600) return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's';
            if (sec < 86400) return Math.floor(sec / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm';
            return Math.floor(sec / 86400) + 'd ' + Math.floor((sec % 86400) / 3600) + 'h';
        }

        async function fetchWithTimeout(url, options = {}, timeoutMs = 5000) {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
            try {
                const response = await fetch(url, withAuth({ ...options, signal: controller.signal }));
                if (response.status === 401) {
                    const ok = await promptForToken();
                    if (ok) {
                        return await fetch(url, withAuth({ ...options, signal: controller.signal }));
                    }
                }
                return response;
            } finally {
                clearTimeout(timeoutId);
            }
        }

        // ===== Security panel: helpers shared by the stats renderer and the
        // peer-encryption detail modal. Declared at script top level so the
        // data-on* delegation layer (which compiles expressions with `new
        // Function`, giving them only global scope) can resolve them.
        let encCache = [];
        let currentPeerEnc = null;

        // Format a raw hex fingerprint as colon-separated pairs for readability.
        // Falls back to a single dash when the value is missing/placeholder.
        function fmtFingerprint(fp) {
            if (!fp || fp === 'unknown') return '—';
            const hex = String(fp).toLowerCase().replace(/[^0-9a-f]/g, '');
            if (hex.length < 2) return fp;
            const groups = hex.match(/.{1,2}/g).slice(0, 8);
            return groups.join(':');
        }

        function shortPeerId(pid) {
            if (!pid) return '—';
            return pid.length > 16 ? (pid.slice(0, 8) + '…' + pid.slice(-4)) : pid;
        }

        // Sort priority for the per-peer list: PFS+encrypted → encrypted(no PFS) →
        // plaintext. Operators want secure links at the top.
        function rankPeer(e) {
            if (e.algo && e.algo !== 'none' && e.encrypted && e.pfs) return 0;
            if (e.algo && e.algo !== 'none' && e.encrypted) return 1;
            return 2;
        }

        function flashCopyBtn(btn) {
            if (!btn) return;
            btn.classList.add('copied');
            setTimeout(function () { btn.classList.remove('copied'); }, 900);
        }

        function copySecFingerprint() {
            const el = document.getElementById('secFingerprint');
            const btn = document.getElementById('secCopyFpBtn');
            if (!el) return;
            const full = el.getAttribute('title') || '';
            if (!full) return;
            copyToClipboard(full).then(function () { flashCopyBtn(btn); });
        }

        function copyPeerEncField(field) {
            if (!currentPeerEnc) return;
            let val = '';
            switch (field) {
                case 'id':  val = currentPeerEnc.peer_id || ''; break;
                case 'tx':  val = currentPeerEnc.tx_key_fp || ''; break;
                case 'rx':  val = currentPeerEnc.rx_key_fp || ''; break;
                case 'pfs': val = currentPeerEnc.pfs_pubkey_fp || ''; break;
            }
            if (!val) return;
            copyToClipboard(val).then(function () {
                const btn = document.querySelector(
                    '#peerEncModalBody [data-copy-field="' + field + '"]'
                );
                flashCopyBtn(btn);
            });
        }

        function openPeerEncModal(idx) {
            const e = encCache[idx];
            if (!e) return;
            currentPeerEnc = e;
            const modal = document.getElementById('peerEncModal');
            const body = document.getElementById('peerEncModalBody');
            if (!modal || !body) return;
            body.innerHTML = '';
            body.appendChild(buildPeerEncDetail(e));
            modal.classList.add('active');
        }

        function closePeerEncModal() {
            const modal = document.getElementById('peerEncModal');
            if (modal) modal.classList.remove('active');
            currentPeerEnc = null;
        }

        // Build the per-peer compact row used in the Security card.
        function buildEncPeerRow(e, idx) {
            const row = document.createElement('div');
            row.className = 'enc-peer-row';
            if (!e.algo || e.algo === 'none') row.classList.add('is-plain');
            row.setAttribute('data-onclick', 'openPeerEncModal(' + idx + ')');
            row.title = t('sec_click_details');

            const head = document.createElement('div');
            head.className = 'enc-peer-head';

            const id = document.createElement('code');
            id.className = 'enc-peer-id';
            id.textContent = shortPeerId(e.peer_id);
            id.title = e.peer_id || '';
            head.appendChild(id);

            const badges = document.createElement('span');
            badges.className = 'enc-peer-badges';

            if (!e.algo || e.algo === 'none') {
                const np = document.createElement('span');
                np.className = 'enc-no-pfs'; np.textContent = '○ no PFS';
                badges.appendChild(np);
                const pl = document.createElement('span');
                pl.className = 'enc-plain'; pl.textContent = 'plaintext';
                badges.appendChild(pl);
            } else {
                if (e.pfs) {
                    const p = document.createElement('span');
                    p.className = 'enc-pfs'; p.textContent = '⚡ PFS';
                    if (e.pfs_pubkey_fp) p.title = 'ECDH fp: ' + e.pfs_pubkey_fp;
                    badges.appendChild(p);
                } else {
                    const w = document.createElement('span');
                    w.className = 'enc-no-pfs'; w.textContent = '⚠ long-lived';
                    badges.appendChild(w);
                }
                const a = document.createElement('span');
                a.className = e.algo === 'chacha20' ? 'enc-algo-chacha' : 'enc-algo-aes';
                a.textContent = '🔒 ' + (e.algo || '');
                badges.appendChild(a);
            }
            head.appendChild(badges);
            row.appendChild(head);

            if (e.tx_key_fp || e.rx_key_fp || e.conn_epoch || e.local_epoch) {
                const keys = document.createElement('div');
                keys.className = 'enc-peer-keys';
                if (e.tx_key_fp) {
                    const tx = document.createElement('span');
                    tx.className = 'enc-tx';
                    tx.appendChild(document.createTextNode('TX '));
                    const tc = document.createElement('code');
                    tc.textContent = e.tx_key_fp;
                    tx.appendChild(tc);
                    keys.appendChild(tx);
                }
                if (e.rx_key_fp) {
                    const rx = document.createElement('span');
                    rx.className = 'enc-rx';
                    rx.appendChild(document.createTextNode('RX '));
                    const rc = document.createElement('code');
                    rc.textContent = e.rx_key_fp;
                    rx.appendChild(rc);
                    keys.appendChild(rx);
                }
                if (e.conn_epoch || e.local_epoch) {
                    const ep = document.createElement('span');
                    ep.className = 'enc-epoch';
                    ep.textContent = 'epoch ' + (e.conn_epoch || '?');
                    ep.title = 'local ' + (e.local_epoch || '?') +
                               ' / peer ' + (e.conn_epoch || '?');
                    keys.appendChild(ep);
                }
                row.appendChild(keys);
            }
            return row;
        }

        // Build the modal body for a single peer (two-column key/value + copy).
        function buildPeerEncDetail(e) {
            const wrap = document.createElement('div');
            wrap.className = 'peer-enc-detail';

            const makeCopyBtn = function (field) {
                const btn = document.createElement('button');
                btn.className = 'btn-copy';
                btn.setAttribute('data-copy-field', field);
                btn.setAttribute('data-onclick',
                    "copyPeerEncField('" + field + "')");
                btn.title = t('sec_copy');
                btn.setAttribute('aria-label', t('sec_copy'));
                btn.innerHTML =
                    '<svg class="ico" aria-hidden="true">' +
                    '<use href="#ic-copy"/></svg>';
                return btn;
            };

            const addTextRow = function (keyI18n, valueText, opts) {
                opts = opts || {};
                const row = document.createElement('div');
                row.className = 'ped-row';
                const k = document.createElement('div');
                k.className = 'ped-key';
                k.textContent = t(keyI18n);
                const v = document.createElement('div');
                v.className = 'ped-val' + (opts.valCls ? ' ' + opts.valCls : '');
                if (opts.code) {
                    const c = document.createElement('code');
                    c.textContent = valueText;
                    v.appendChild(c);
                } else {
                    v.textContent = valueText;
                }
                const a = document.createElement('div');
                if (opts.copyField) a.appendChild(makeCopyBtn(opts.copyField));
                row.appendChild(k); row.appendChild(v); row.appendChild(a);
                wrap.appendChild(row);
            };

            addTextRow('sec_peer_id', e.peer_id || '—', { code: true, copyField: 'id' });
            addTextRow('sec_peer_algo', e.algo || 'none');
            addTextRow('sec_peer_pfs',
                e.pfs ? t('sec_yes') : t('sec_no'),
                { valCls: e.pfs ? 'ped-yes' : 'ped-no' });
            if (e.tx_key_fp) addTextRow('sec_peer_tx_fp', e.tx_key_fp,
                { code: true, copyField: 'tx', valCls: 'ped-tx' });
            if (e.rx_key_fp) addTextRow('sec_peer_rx_fp', e.rx_key_fp,
                { code: true, copyField: 'rx', valCls: 'ped-rx' });
            if (e.pfs && e.pfs_pubkey_fp) addTextRow('sec_peer_pfs_eph',
                e.pfs_pubkey_fp,
                { code: true, copyField: 'pfs' });
            addTextRow('sec_peer_epoch_local',
                (e.local_epoch != null && e.local_epoch !== '') ? String(e.local_epoch) : '—');
            addTextRow('sec_peer_epoch_peer',
                (e.conn_epoch != null && e.conn_epoch !== '') ? String(e.conn_epoch) : '—');

            return wrap;
        }

        // Replace the per-peer encryption list DOM in one go. Sorted so secure
        // peers surface first.
        function renderEncList(enc) {
            const list = document.getElementById('encList');
            const cnt = document.getElementById('encCount');
            if (!list || !cnt) return;
            cnt.textContent = enc.length;
            encCache = enc.slice();
            list.innerHTML = '';
            if (enc.length === 0) {
                const empty = document.createElement('div');
                empty.className = 'empty-row';
                empty.setAttribute('data-i18n', 'no_peers_enc');
                empty.textContent = t('no_peers_enc');
                list.appendChild(empty);
                return;
            }
            const sorted = enc.slice().sort(function (a, b) {
                return rankPeer(a) - rankPeer(b);
            });
            for (let i = 0; i < sorted.length; i++) {
                const realIdx = enc.indexOf(sorted[i]);
                list.appendChild(buildEncPeerRow(sorted[i], realIdx));
            }
        }

        let isFetchingStats = false;
        async function fetchStats() {
            if (isFetchingStats) return;
            if (document.hidden) return;
            isFetchingStats = true;
            try {
                const now = Date.now();
                const res = await fetchWithTimeout('/api/stats', {}, 4000);
                if (!res.ok) return;
                const data = await res.json();
                latestStatsData = data;
                window.__lastStatsData = data;

                // Pull the full mesh topology (link-state graph) in the same tick so
                // the topology view can render a hierarchical tree (relay nodes above
                // the peers they transit). Failure is non-fatal: we fall back to the
                // star layout built from active_peers.
                try {
                    const tres = await fetchWithTimeout('/api/topology', {}, 4000);
                    if (tres.ok) latestTopologyData = await tres.json();
                } catch (e) { /* keep previous topology */ }

                // Title & Badges
                if (data.node_name) {
                    document.getElementById('nodeName').innerText = data.node_name;
                    localNodeInfo.name = data.node_name;
                } else {
                    document.getElementById('nodeName').innerText = t('default_node_name');
                }
                
                if (data.peer_id) {
                    document.getElementById('nodePeerID').innerHTML = `<span data-i18n="peer_id_lbl">${t('peer_id_lbl')}</span>: ${escapeHTML(data.peer_id)}`;
                    localNodeInfo.peerID = data.peer_id;
                }

                if (data.version) {
                    const verStr = data.version.startsWith('v') ? data.version : ('v' + data.version);
                    const verEl = document.getElementById('appVersion');
                    if (verEl) verEl.innerText = verStr;
                }
                
                const strategyStr = (data.transport_strategy || 'best_path').toLowerCase();
                document.getElementById('strategyBadge').innerText = t('strategy_' + strategyStr) || strategyStr.toUpperCase();

                // TAP IPs
                document.getElementById('tapIPv4').innerText = data.tap_ip || t('not_configured');
                document.getElementById('tapIPv6').innerText = data.tap_ipv6 || t('not_configured');
                if (data.tap_ip) localNodeInfo.ip = data.tap_ip;
                if (data.tap_ipv6) localNodeInfo.ipv6 = data.tap_ipv6;

                // Traffic Stats & Speedometer
                const stats = data.packet_stats || {};
                const currentTx = stats.bytes_sent || 0;
                const currentRx = stats.bytes_recv || 0;
                const timeDiffSec = Math.max((now - lastFetchTime) / 1000, 0.5);

                // Real-Time Speedometer
                const speed = data.speed || {};
                if (speed.tx_bytes_per_sec !== undefined) {
                    document.getElementById('txSpeed').innerText = formatSpeed(speed.tx_bytes_per_sec);
                }
                if (speed.rx_bytes_per_sec !== undefined) {
                    document.getElementById('rxSpeed').innerText = formatSpeed(speed.rx_bytes_per_sec);
                }

                lastTxBytes = currentTx;
                lastRxBytes = currentRx;
                lastFetchTime = now;

                document.getElementById('txBytes').innerText = formatBytes(currentTx);
                document.getElementById('txPackets').innerHTML = `<span data-i18n="pkts_total">${t('pkts_total')}</span>` + (stats.packets_sent || 0) + ' pkts';
                document.getElementById('rxBytes').innerText = formatBytes(currentRx);
                document.getElementById('rxPackets').innerHTML = `<span data-i18n="pkts_total">${t('pkts_total')}</span>` + (stats.packets_recv || 0) + ' pkts';
                document.getElementById('dedupCount').innerText = stats.dedup_count || 0;

                // System & Go Runtime Health
                const sys = data.system || {};
                if (sys.heap_alloc_mb !== undefined) {
                    document.getElementById('sysHeap').innerText = `${sys.heap_alloc_mb.toFixed(1)} MB / ${sys.sys_mem_mb.toFixed(1)} MB`;
                    if (sys.heap_inuse_mb !== undefined) document.getElementById('sysHeapInuse').innerText = `${sys.heap_inuse_mb.toFixed(1)} MB`;
                    if (sys.heap_objects !== undefined) document.getElementById('sysHeapObjects').innerText = sys.heap_objects.toLocaleString();
                    if (sys.stack_inuse_mb !== undefined) document.getElementById('sysStackInuse').innerText = `${sys.stack_inuse_mb.toFixed(1)} MB`;
                    if (sys.next_gc_mb !== undefined) document.getElementById('sysNextGC').innerText = `${sys.next_gc_mb.toFixed(1)} MB`;
                    if (sys.last_gc_pause_ms !== undefined) document.getElementById('sysLastGCPause').innerText = `${sys.last_gc_pause_ms.toFixed(2)} ms`;
                    if (sys.gc_cpu_fraction !== undefined) {
                        const pct = (sys.gc_cpu_fraction * 100);
                        const elGCCPU = document.getElementById('sysGCCPUFrac');
                        elGCCPU.innerText = `${pct.toFixed(2)} %`;
                        // colour-code: <5% green (healthy), 5-25% amber, >25% red (GC pressure)
                        if (pct < 5) elGCCPU.style.color = '#34d399';
                        else if (pct < 25) elGCCPU.style.color = '#fbbf24';
                        else elGCCPU.style.color = '#f87171';
                    }
                    document.getElementById('sysGoroutines').innerText = sys.goroutines || 0;
                    document.getElementById('sysGC').innerText = sys.gc_count || 0;
                    if (sys.num_cpu !== undefined) document.getElementById('sysNumCPU').innerText = sys.num_cpu;
                    if (sys.gomaxprocs !== undefined) document.getElementById('sysGOMAXPROCS').innerText = sys.gomaxprocs;
                    const upSec = sys.uptime_seconds || 0;
                    const upMin = Math.floor(upSec / 60);
                    const upHour = Math.floor(upMin / 60);
                    const upStr = upHour > 0 ? `${upHour}h ${upMin % 60}m` : `${upMin}m ${upSec % 60}s`;
                    document.getElementById('sysUptime').innerText = upStr;
                    // GC pause colour: <1ms green, 1-10ms amber, >10ms red (latency stability indicator)
                    const pauseEl = document.getElementById('sysLastGCPause');
                    if (sys.last_gc_pause_ms !== undefined) {
                        if (sys.last_gc_pause_ms < 1) pauseEl.style.color = '#34d399';
                        else if (sys.last_gc_pause_ms < 10) pauseEl.style.color = '#fbbf24';
                        else pauseEl.style.color = '#f87171';
                    }
                }

                // Security & Crypto Status
                const sec = data.security || {};
                if (sec.psk_status) {
                    let pskText = sec.psk_status;
                    if (pskText.includes('Public')) pskText = '🌐 ' + t('public_unencrypted');
                    else if (pskText.includes('Encrypted')) pskText = '🔐 ' + t('encrypted_overlay');
                    document.getElementById('secPSK').innerText = pskText;

                    let obfsText = sec.obfuscation || t('disabled');
                    if (obfsText === 'Disabled') obfsText = t('disabled');
                    document.getElementById('secObfs').innerText = obfsText;

                    const fullFp = (sec.key_fingerprint && sec.key_fingerprint !== 'unknown') ? sec.key_fingerprint : '';
                    const fpEl = document.getElementById('secFingerprint');
                    const fpBtn = document.getElementById('secCopyFpBtn');
                    if (fpEl) {
                        fpEl.textContent = fullFp ? fmtFingerprint(fullFp) : '—';
                        if (fullFp) fpEl.setAttribute('title', fullFp); else fpEl.removeAttribute('title');
                    }
                    if (fpBtn) fpBtn.disabled = !fullFp;
                    
                    let natText = data.nat_status || 'Public';
                    if (natText === 'Public') natText = t('public_direct');
                    document.getElementById('secNAT').innerText = natText;
                }

                // Per-peer encryption breakdown (sorted: PFS → encrypted → plaintext).
                renderEncList(sec.encryption || []);

                // Protocol Distribution Bar & Counters
                const proto = data.protocol_stats || {};
                const pIPv4 = proto.ipv4 || 0;
                const pIPv6 = proto.ipv6 || 0;
                const pARP = proto.arp || 0;
                const pNDP = proto.ndp || 0;
                const pICMP = proto.icmp || 0;
                const pUDP = proto.udp || 0;
                const pTCP = proto.tcp || 0;
                const pOther = proto.other || 0;
                const pTotal = pIPv4 + pIPv6 + pARP + pNDP + pICMP + pUDP + pTCP + pOther;

                // Compute proportional bar widths (avoid divide-by-zero).
                const pDenom = pTotal > 0 ? pTotal : 1;
                const setBar = (id, val) => {
                    const el = document.getElementById(id);
                    if (el) el.style.width = ((val / pDenom) * 100).toFixed(2) + '%';
                };
                setBar('barIPv4', pIPv4);
                setBar('barIPv6', pIPv6);
                setBar('barARP', pARP);
                setBar('barNDP', pNDP);
                setBar('barICMP', pICMP);
                setBar('barUDP', pUDP);
                setBar('barTCP', pTCP);
                setBar('barOther', pOther);

                document.getElementById('protoTotalPkts').innerText = `${pTotal} pkts`;
                document.getElementById('cntIPv4').innerText = pIPv4;
                document.getElementById('cntIPv6').innerText = pIPv6;
                document.getElementById('cntARP').innerText = pARP;
                document.getElementById('cntNDP').innerText = pNDP;
                document.getElementById('cntICMP').innerText = pICMP;
                document.getElementById('cntUDP').innerText = pUDP;
                document.getElementById('cntTCP').innerText = pTCP;
                document.getElementById('cntOther').innerText = pOther;

                if (data.protocol_stats) {
                    document.getElementById('pktStatICMP').innerText = data.protocol_stats.icmp || 0;
                    document.getElementById('pktStatUDP').innerText = data.protocol_stats.udp || 0;
                    document.getElementById('pktStatTCP').innerText = data.protocol_stats.tcp || 0;
                }

                // Broadcast / Multicast / Gateway classification from the
                // dedicated gateway_packets block (lock-free backend counters).
                if (data.gateway_packets) {
                    const gp = data.gateway_packets;
                    document.getElementById('pktStatBroadcast').innerText = gp.broadcast || 0;
                    document.getElementById('pktStatMulticast').innerText = gp.multicast || 0;
                    document.getElementById('pktStatGateway').innerText = gp.gateway || 0;
                }

                // Structured-SeqID diagnostics: synced peers + replay/window drops.
                if (data.seq_stats) {
                    const ss = data.seq_stats;
                    document.getElementById('pktStatSeqSync').innerText = `${ss.synced_peers}`;
                    const seqHint = `replay ${ss.replay_drops || 0} · win-reset ${ss.window_resets || 0} · util ${(ss.win_utilization * 100).toFixed(1)}%`;
                    const seqEl = document.getElementById('pktStatSeqSync');
                    if (seqEl && seqEl.parentElement) {
                        const sub = seqEl.parentElement.querySelector('div:last-child');
                        if (sub) sub.innerText = seqHint;
                    }
                }

                if (pTotal > 0) {
                    document.getElementById('barIPv4').style.width = `${((pIPv4 / pTotal) * 100).toFixed(1)}%`;
                    document.getElementById('barIPv6').style.width = `${((pIPv6 / pTotal) * 100).toFixed(1)}%`;
                    document.getElementById('barARP').style.width = `${((pARP / pTotal) * 100).toFixed(1)}%`;
                    document.getElementById('barOther').style.width = `${((pOther / pTotal) * 100).toFixed(1)}%`;
                }

                // Active Peers Table & Mesh Canvas Update
                const peers = data.active_peers || [];
                cachedPeers = peers;
                drawTopologyMesh();
                populateTroubleshooterDropdown();

                document.getElementById('peersCount').innerText = peers.length;
                const peersBody = document.getElementById('peersList');
                if (peers.length > 0) {
                    peersBody.innerHTML = peers.map(p => {
                        // Reachability: prefer the peer's self-reported reachability ("Public" = green),
                        // but also detect if our connection to them is relayed from the transport field.
                        const isMyConnRelayed = isPeerRelayed(p);
                        const isPeerPublic = p.reachability === 'Public';
                        let reachClass, reachText;
                        if (isMyConnRelayed) {
                            reachClass = '#fbbf24';
                            reachText = t('relayed_conn') || 'Relayed';
                        } else if (isPeerPublic) {
                            reachClass = '#34d399';
                            reachText = t('public_direct') || 'Public/Direct';
                        } else {
                            reachClass = '#38bdf8';
                            reachText = p.reachability || 'Direct';
                        }
                        const tapIPs = (
                            [p.tap_ip ? `<code class="is-v4">${escapeHTML(p.tap_ip)}</code>` : '',
                             p.tap_ipv6 ? `<code class="is-v6">${escapeHTML(p.tap_ipv6)}</code>` : '']
                                .join('')
                        ) || '<code class="is-v4 empty">-</code>';
                        const roleBadge = p.role === 'Bootstrap' 
                            ? '<span class="pill-badge role-bootstrap">🟣 Bootstrap</span>'
                            : (p.role === 'Static'
                                ? '<span class="pill-badge role-static">🟦 Static</span>'
                                : '<span class="pill-badge role-peer">🟢 Peer</span>');

                        const geoBadge = p.geo_location || '🌐 Public Peer';
                        const jitterStr = (p.jitter_ms || 0.5).toFixed(1);
                        const lossStr = (p.loss_rate_percent || 0.0).toFixed(1);

                        const allAddrsList = (p.all_addrs && p.all_addrs.length > 0) ? p.all_addrs : [p.addr];
                        // Resolve what to show as the "current active pathway":
                        // prefer a real multiaddr in `p.addr`; if it's missing or
                        // the placeholder string "unknown", fall back to the
                        // descriptive `transport` label so the column never lies
                        // about a real multiaddr that doesn't exist.
                        const activeAddrText = (p.addr && p.addr !== 'unknown')
                            ? p.addr
                            : (p.transport || '—');
                        const addrsHoverHtml = `
                            <div class="multiaddr-hover-wrapper">
                                <div style="font-weight:600; color:var(--accent-cyan); word-break:break-all;" title="Current Active Connected Pathway">⚡ ${escapeHTML(activeAddrText)}</div>
                                ${allAddrsList.length > 1 ? `
                                    <button class="btn-multiaddr-view" data-onclick="event.stopPropagation(); openMultiaddrModal(${attrStr(p.peer_id)})">
                                        🛣️ ${allAddrsList.length} ${t('disc_addrs') || 'Discovered Addr Pathways'} (Click to view)
                                    </button>
                                ` : `
                                    <button class="btn-multiaddr-view" data-onclick="event.stopPropagation(); openMultiaddrModal(${attrStr(p.peer_id)})">
                                        ${t('view_addr') || 'View Multiaddr'}
                                    </button>
                                `}
                            </div>
                        `;

                        const isCurrentExit = data.exit_node && data.exit_node.active_peer_id === p.peer_id;
                        let exitBadgeHtml = '';
                        if (p.is_exit_node) {
                            const natText = p.exit_nat ? 'NAT' : 'No-NAT';
                            exitBadgeHtml = `<span class="pill-badge role-static" style="padding:2px 6px; font-size:0.7rem; background:var(--accent-cyan-fill); border-color:var(--accent-cyan-border); color:var(--accent-cyan); margin-top:2px;" title="${t('exit_node_badge') || 'Exit Node Gateway'}">${t('exit_node_badge') || '🌐 Exit Node'} (${natText})</span>`;
                        }
                        if (isCurrentExit) {
                            exitBadgeHtml += `<span class="pill-badge role-bootstrap" style="padding:2px 6px; font-size:0.7rem; margin-top:2px;">${t('active_exit_badge') || '⚡ Active Gateway'}</span>`;
                        }
                        const relayOnlyBadge = p.relay_only
                            ? `<span class="pill-badge role-relay-only" title="${t('relay_only') || 'Relay-Only'}">🌉 ${t('relay_only') || 'Relay-Only'}</span>`
                            : '';

                        const peerTxSpeedStr = formatSpeed(p.tx_speed || 0);
                        const peerRxSpeedStr = formatSpeed(p.rx_speed || 0);
                        const peerTotalTxStr = formatBytes(p.total_tx || 0);
                        const peerTotalRxStr = formatBytes(p.total_rx || 0);

                        return `
                        <tr>
                            <td>
                                <div style="display:flex; flex-direction:column;">
                                    <strong style="color:var(--text-primary); font-size:0.92rem; cursor:pointer;" data-onclick="setPingTarget(${attrStr(p.tap_ip || p.peer_id)})" title="Click to Ping">${escapeHTML(p.node_name) || t('unnamed_node')}</strong>
                                    <div style="display:flex; gap:5px; align-items:center; margin-top:3px; flex-wrap:wrap;">
                                        ${exitBadgeHtml}${relayOnlyBadge}
                                        <span style="font-size:0.7rem; color:var(--success); background:var(--accent-green-fill); padding:1px 6px; border-radius:4px; border:1px solid var(--accent-green-fill);" title="Peer Link Rate: Tx ${peerTotalTxStr}, Rx ${peerTotalRxStr}">
                                            Peer Rate: ⬆️ ${peerTxSpeedStr} | ⬇️ ${peerRxSpeedStr}
                                        </span>
                                    </div>
                                </div>
                            </td>
                            <td><span style="color:var(--text-dim); font-size:0.8rem">${escapeHTML(geoBadge)}</span></td>
                            <td>${roleBadge}</td>
                            <td>
                                <div style="display:flex; flex-direction:column; gap:2px;">
                                    <span style="color:var(--text-dim); font-size:0.8rem; font-weight:500;">${escapeHTML(p.os_arch || 'linux')}</span>
                                    <span style="color:var(--accent-purple); font-size:0.72rem; font-family:monospace;" title="Node Software Version">${escapeHTML(p.version ? (p.version.startsWith('v') ? p.version : 'v' + p.version) : 'dev')}</span>
                                </div>
                            </td>
                            <td><div class="tap-ip-cell">${tapIPs}</div></td>
                            <td><span style="color:${reachClass}; font-size:0.8rem">🟢 ${reachText}</span></td>
                            <td>
                                <div style="display:flex; flex-direction:column; gap:2px;">
                                    ${encBadge(p)}
                                    ${handshakeBadge(p)}
                                </div>
                            </td>
                            <td>${connStateBadge(p)}</td>
                            <td>${returnPathBadge(p)}</td>
                            <td><code>${escapeHTML(p.peer_id)}</code></td>
                            <td style="position:relative;">${addrsHoverHtml}</td>
                            <td><span class="pill-badge" style="padding:3px 10px; font-size:0.75rem">${p.transport || 'P2P'}</span></td>
                            <td><span style="color:var(--accent-purple); font-size:0.82rem;" title="Connected at ${p.connected_at}">${p.connected_since || '-'}</span></td>
                            <td><span style="color:var(--accent-cyan); font-size:0.82rem;">${p.last_seen || 'Just now'}</span></td>
                            <td><strong style="color:${p.rtt_ms < 50 ? 'var(--success)' : (p.rtt_ms < 150 ? 'var(--warn)' : 'var(--danger)')}">${p.rtt_ms} ms</strong></td>
                            <td><span style="color:var(--accent-purple); font-size:0.8rem">±${jitterStr} ms</span> <span style="color:var(--text-muted); font-size:0.75rem">(${lossStr}%)</span></td>
                            <td>
                                <div style="display:flex; gap:6px; align-items:center;">
                                    <button class="btn-glass" style="padding:2px 8px; font-size:0.75rem; background:var(--accent-cyan-fill); border-color:var(--accent-cyan-border);" data-onclick="openSpeedTestModal(${attrStr(p.peer_id)})">${t('speedtest_btn')}</button>
                                </div>
                            </td>
                        </tr>
                    `}).join('');
                } else {
                    peersBody.innerHTML = `<tr><td colspan="17" class="empty-row" data-i18n="no_peers">${t('no_peers')}</td></tr>`;
                }

                // Peer Metadata & Peek-Map Discovery Monitor
                const peerMetas = data.peer_metas || [];
                const peerMetaCountEl = document.getElementById('peerMetaCount');
                if (peerMetaCountEl) peerMetaCountEl.innerText = peerMetas.length;
                const peerMetaBody = document.getElementById('peerMetaList');
                if (peerMetaBody) {
                    if (peerMetas.length > 0) {
                        peerMetaBody.innerHTML = peerMetas.map(m => {
                            const subnetsHtml = (m.advertised_subnets && m.advertised_subnets.length > 0)
                                ? m.advertised_subnets.map(s => `<span style="background:var(--accent-green-fill); color:var(--success); padding:2px 7px; border-radius:5px; font-family:monospace; font-size:0.76rem; border:1px solid var(--accent-green-fill); margin:2px;">${escapeHTML(s)}</span>`).join(' ')
                                : '<span style="color:var(--text-muted);">-</span>';

                            const exitHtml = m.is_exit_node
                                ? `<span style="color:var(--success); font-weight:600; font-size:0.78rem;">🌐 Exit Server${m.exit_nat ? ' (NAT)' : ''}</span>`
                                : '<span style="color:var(--text-muted);">-</span>';

                            const channelColor = m.sync_source && m.sync_source.includes('Peek-Map') ? '#fbbf24' : '#38bdf8';
                            const channelBadge = `<span style="background:var(--glass-fill); border:1px solid var(--glass-fill-strong); color:${channelColor}; font-weight:600; padding:2px 8px; border-radius:6px; font-size:0.75rem;">${escapeHTML(m.sync_source || 'P2P / LSA')}</span>`;

                            let tapAddrs = '';
                            if (m.tap_ip && m.tap_ip !== '-') {
                                tapAddrs += `<code class="is-v4">${escapeHTML(m.tap_ip)}</code>`;
                            }
                            if (m.tap_ipv6 && m.tap_ipv6 !== '-') {
                                tapAddrs += `<code class="is-v6">${escapeHTML(m.tap_ipv6)}</code>`;
                            }
                            if (!tapAddrs) tapAddrs = '<code class="is-v4 empty">-</code>';
                            const tapAddrsCell = tapAddrs ? `<div class="tap-ip-cell">${tapAddrs}</div>` : '<code class="is-v4 empty">-</code>';

                            return `
                                <tr>
                                    <td><strong style="color:var(--text-primary); font-size:0.88rem;">${escapeHTML(m.node_name || t('unnamed_node'))}</strong></td>
                                    <td><code style="font-size:0.78rem;">${escapeHTML(m.peer_id)}</code></td>
                                    <td>${tapAddrsCell}</td>
                                    <td><code style="color:var(--accent-purple); font-size:0.8rem;">${escapeHTML(m.tap_mac || '-')}</code></td>
                                    <td>
                                        <div style="display:flex; flex-direction:column; gap:2px;">
                                            <span style="color:var(--text-dim); font-size:0.78rem;">${escapeHTML(m.os_arch || 'linux')}</span>
                                            <span style="color:var(--accent-purple); font-size:0.72rem; font-family:monospace;">${escapeHTML(m.version || 'dev')}</span>
                                        </div>
                                    </td>
                                    <td><div style="display:flex; flex-wrap:wrap;">${subnetsHtml}</div></td>
                                    <td>${exitHtml}</td>
                                    <td>${channelBadge}</td>
                                    <td><span style="color:var(--text-dim); font-size:0.8rem;">${escapeHTML(m.last_sync || '-')}</span></td>
                                </tr>
                            `;
                        }).join('');
                    } else {
                        peerMetaBody.innerHTML = `<tr><td colspan="9" class="empty-row" data-i18n="no_peer_metas">${t('no_peer_metas') || 'No peer metadata received via peek-map / P2P'}</td></tr>`;
                    }
                }

                renderExitStatus(data);
                renderExitClientCard(data);
                renderACLCard(data);
                renderProtocolChannels(data);

                // ARP Table
                const arps = data.arp_table || [];
                document.getElementById('arpCount').innerText = arps.length;
                const arpBody = document.getElementById('arpList');
                if (arps.length > 0) {
                    arpBody.innerHTML = arps.map(a => `
                        <tr>
                            <td><code style="color:var(--accent-cyan); font-weight:bold">${escapeHTML(a.ip)}</code></td>
                            <td><code style="color:var(--accent-purple)">${escapeHTML(a.mac)}</code></td>
                            <td><strong style="color:var(--text-primary); font-size:0.9rem">${escapeHTML(a.node_name) || t('unnamed_node')}</strong></td>
                            <td><code>${escapeHTML(a.peer_id)}</code></td>
                            <td><span class="pill-badge" style="padding:3px 10px; font-size:0.75rem">${a.type}</span></td>
                            <td style="color:var(--text-secondary)">${a.last_seen}</td>
                        </tr>
                    `).join('');
                } else {
                    arpBody.innerHTML = `<tr><td colspan="6" class="empty-row" data-i18n="no_arps">${t('no_arps')}</td></tr>`;
                }

                // IP Traffic Analytics Table (paginated + searchable; see renderIpTable)
                allIpRows = data.ip_table || [];
                renderIpTable();

                // Smart P2P Overlay Routing Table
                cachedRoutes = data.routes_table || [];
                transitRelaySet.clear();
                let relayedCount = 0;
                let maxSavedMs = 0;

                cachedRoutes.forEach(r => {
                    if (!r.is_direct && r.next_hop_peer) {
                        transitRelaySet.add(r.next_hop_peer);
                        relayedCount++;
                    }
                    if (r.saved_rtt_ms > maxSavedMs) {
                        maxSavedMs = r.saved_rtt_ms;
                    }
                });

                document.getElementById('routeCount').innerText = cachedRoutes.length;
                const statTotal = document.getElementById('statTotalRoutes');
                if (statTotal) statTotal.innerText = cachedRoutes.length;
                const statRelay = document.getElementById('statRelayedRoutes');
                if (statRelay) statRelay.innerText = relayedCount;
                const statSaved = document.getElementById('statMaxSavings');
                if (statSaved) statSaved.innerText = maxSavedMs > 0 ? `⚡ -${maxSavedMs} ms` : `0 ms`;

                const routeBody = document.getElementById('routeList');
                if (cachedRoutes.length > 0) {
                    routeBody.innerHTML = cachedRoutes.map(r => {
                        const hopCount = (r.path && r.path.length > 1) ? r.path.length - 1 : 1;
                        
                        // Render visual hop pills
                        let visualPath = '';
                        if (r.path_names && r.path_names.length > 0) {
                            visualPath = r.path_names.map((name, idx) => {
                                if (idx === 0) {
                                    return `<span style="background:var(--accent-cyan-fill); border:1px solid var(--accent-cyan-border); color:var(--accent-cyan); border-radius:5px; padding:2px 7px; font-size:0.78rem; font-weight:600;">💻 Local</span>`;
                                } else if (idx === r.path_names.length - 1) {
                                    return `<span style="background:var(--accent-green-fill); border:1px solid var(--accent-green-border); color:var(--success); border-radius:5px; padding:2px 7px; font-size:0.78rem; font-weight:600;">🎯 ${name}</span>`;
                                } else {
                                    return `<span style="background:var(--accent-purple-fill); border:1px solid var(--accent-purple-border); color:var(--accent-purple); border-radius:5px; padding:2px 7px; font-size:0.78rem; font-weight:600;">🔀 ${name}</span>`;
                                }
                            }).join('<span style="color:var(--text-muted); margin:0 4px; font-size:0.75rem;">➔</span>');
                        } else {
                            visualPath = `<code style="color:var(--accent-purple)">${r.dest_name}</code>`;
                        }

                        // Render Smart Optimization Progress Bar & Gain Badge
                        let optHtml = `<div style="display:flex; align-items:center; gap:6px;"><span style="color:var(--text-secondary); font-size:0.8rem;">Direct Route</span><span style="color:var(--text-secondary); font-size:0.7rem; background:var(--border-subtle); padding:1px 6px; border-radius:4px;">Optimal</span></div>`;
                        if (r.saved_rtt_ms > 0 && r.direct_rtt_ms > 0) {
                            const percent = Math.min(100, Math.round((r.saved_rtt_ms * 100) / r.direct_rtt_ms));
                            optHtml = `
                                <div style="display:flex; flex-direction:column; gap:3px; min-width:120px;">
                                    <div style="display:flex; align-items:center; justify-content:space-between; font-size:0.78rem;">
                                        <span style="color:var(--success); font-weight:bold;">⚡ -${r.saved_rtt_ms} ms</span>
                                        <span style="color:var(--success); font-size:0.7rem; background:var(--accent-green-fill); padding:1px 5px; border-radius:4px; font-weight:bold;">+${percent}% Faster</span>
                                    </div>
                                    <div style="width:100%; height:5px; background:var(--glass-fill-strong); border-radius:3px; overflow:hidden;">
                                        <div style="width:${percent}%; height:100%; background:linear-gradient(90deg, var(--success), var(--success)); border-radius:3px;"></div>
                                    </div>
                                </div>
                            `;
                        }

                        // Transport path is the ACTUAL path (direct / circuit-relay /
                        // overlay-relay). A circuit-relayed peer is flagged IsDirect=true
                        // by the routing layer, so checking is_direct alone would wrongly
                        // label a 500ms+ relayed peer as "Direct".
                        let statusBadge;
                        if (r.transport_path === 'circuit-relay') {
                            statusBadge = `<span class="pill-badge role-bootstrap" style="padding:3px 9px; font-size:0.75rem;">🔄 Circuit Relay</span>`;
                        } else if (!r.is_direct) {
                            statusBadge = `<span class="pill-badge role-bootstrap" style="padding:3px 9px; font-size:0.75rem;">🔀 Relayed via ${r.next_hop_name}</span>`;
                        } else {
                            statusBadge = `<span class="pill-badge role-static" style="padding:3px 9px; font-size:0.75rem;">⚡ Direct</span>`;
                        }
                        const directText = r.direct_rtt_ms > 0 ? `${r.direct_rtt_ms} ms` : '-';
                        const hopBadge = `<span style="white-space:nowrap; background:var(--glass-fill); border:1px solid var(--glass-fill-strong); color:var(--text-dim); padding:2px 8px; border-radius:12px; font-size:0.75rem;">${hopCount} ${hopCount === 1 ? 'Hop' : 'Hops'}</span>`;

                        let ipHtml = '';
                        if (r.tap_ip && r.tap_ip !== '-') {
                            ipHtml += `<div style="line-height:1.2;"><code style="color:var(--accent-cyan); font-weight:bold; cursor:pointer;" data-onclick="setPingTarget(${attrStr(r.tap_ip)})" title="Click to ping IPv4">${escapeHTML(r.tap_ip)}</code></div>`;
                        }
                        if (r.tap_ipv6 && r.tap_ipv6 !== '-') {
                            ipHtml += `<div style="line-height:1.2; margin-top:2px;"><code style="color:var(--accent-purple); font-weight:bold; font-size:0.75rem; cursor:pointer;" data-onclick="setPingTarget(${attrStr(r.tap_ipv6)})" title="Click to ping IPv6">${escapeHTML(r.tap_ipv6)}</code></div>`;
                        }
                        if (!ipHtml) {
                            ipHtml = '<span style="color:var(--text-muted);">-</span>';
                        }

                        return `
                            <tr>
                                <td><strong style="color:var(--text-primary); font-size:0.9rem">${r.dest_name}</strong></td>
                                <td>${ipHtml}</td>
                                <td>${hopBadge}</td>
                                <td><div style="display:flex; align-items:center; flex-wrap:wrap;">${visualPath}</div></td>
                                <td><strong style="color:${r.total_rtt_ms < 50 ? 'var(--success)' : 'var(--warn)'}">${r.total_rtt_ms} ms</strong></td>
                                <td style="color:var(--text-secondary)">${directText}</td>
                                <td>${optHtml}</td>
                                <td>${statusBadge}</td>
                                <td><button class="btn-glass" style="padding:3px 9px; font-size:0.75rem; background:var(--accent-cyan-fill); border-color:var(--accent-cyan-border);" data-onclick="inspectRoute(${attrStr(r.dest_peer)})" data-i18n="inspect_btn">🔍 Inspect</button></td>
                            </tr>
                        `;
                    }).join('');
                } else {
                    routeBody.innerHTML = `<tr><td colspan="9" class="empty-row" data-i18n="no_routes">${t('no_routes')}</td></tr>`;
                }

                // MAC Table
                const macs = data.mac_table || [];
                document.getElementById('macCount').innerText = macs.length;
                window.renderMacTable(macs);

                // Bandwidth Waveform Chart
                if (data.speed_history) {
                    drawBandwidthChart(data.speed_history);
                    drawPacketRateChart(data.speed_history);
                }

                // Mesh Quality Matrix
                const matrixBody = document.getElementById('meshMatrixTableBody');
                if (matrixBody) {
                    const matrix = data.mesh_matrix || [];
                    if (matrix.length > 0) {
                        matrixBody.innerHTML = matrix.map(m => {
                            const rttColor = m.rtt_ms < 50 ? '#34d399' : (m.rtt_ms < 150 ? '#fbbf24' : '#f87171');
                            const typeBadge = m.is_direct ? `<span style="color:var(--accent-cyan); font-weight:bold;">⚡ Direct P2P</span>` : `<span style="color:var(--accent-purple); font-weight:bold;">🔀 Multi-Hop Relay</span>`;
                            return `
                                <tr>
                                    <td><strong style="color:var(--text-primary);">💻 ${escapeHTML(m.src_name)}</strong></td>
                                    <td><strong style="color:var(--accent-cyan); cursor:pointer;" data-onclick="setPingTarget(${attrStr(m.dst_peer_id)})">🎯 ${escapeHTML(m.dst_name)}</strong></td>
                                    <td><strong style="color:${rttColor}">${m.rtt_ms} ms</strong></td>
                                    <td><span class="pill-badge role-static" style="font-size:0.75rem;">${m.hops} Hops</span></td>
                                    <td>${typeBadge}</td>
                                </tr>
                            `;
                        }).join('');
                    } else {
                        matrixBody.innerHTML = `<tr><td colspan="5" class="empty-row" data-i18n="no_matrix">${t('no_matrix')}</td></tr>`;
                    }
                }

                // Subnet Routes
                const subnetListEl = document.getElementById('subnetRoutesList');
                const subnetBadgeEl = document.getElementById('subnetCountBadge');
                if (subnetListEl && subnetBadgeEl) {
                    const subnets = data.subnet_routes || [];
                    subnetBadgeEl.innerText = `${subnets.length} Subnets`;
                    renderSubnetList(subnetListEl, subnets);
                }

                // Duplicate IP / Subnet Conflicts
                const dupEl = document.getElementById('dupIpConflictsList');
                const dupBadge = document.getElementById('dupIpCountBadge');
                if (dupEl && dupBadge) {
                    const conflicts = data.duplicate_ip_conflicts || [];
                    dupBadge.innerText = String(conflicts.length);
                    dupBadge.setAttribute('data-zero', conflicts.length === 0 ? 'true' : 'false');
                    renderDupConflicts(dupEl, conflicts);
                }

            } catch (e) {
                console.error("Fetch stats error:", e);
            } finally {
                isFetchingStats = false;
            }
        }

        // Render the "Subnet Routes" list with rows following the numbered-tag
// pattern. Lines that can never be written into the local routing table
// Render the Virtual Switch MAC Table with source disambiguation. Pure DOM
// builder (no inline styles): each row is tagged `self` (the peer's own virtual
// TAP interface) or `lan` (a device behind the peer, forwarded through it). A
// per-peer warning fires when a peer relays more than one LAN device, which is
// exactly the "why does one peer have many MACs?" case.
window.renderMacTable = function(macs) {
    const macBody = document.getElementById('macList');
    const warnWrap = document.getElementById('macWarnWrap');
    if (!macs || macs.length === 0) {
        macBody.innerHTML = `<tr><td colspan="4" class="empty-row" data-i18n="no_macs">${t('no_macs')}</td></tr>`;
        warnWrap.replaceChildren();
        warnWrap.hidden = true;
        return;
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const STALE_SEC = 300;
    const sorted = macs.slice().sort((a, b) => {
        if (a.peer_id !== b.peer_id) return a.peer_id < b.peer_id ? -1 : 1;
        const oa = a.origin === 'self' ? 0 : 1;
        const ob = b.origin === 'self' ? 0 : 1;
        if (oa !== ob) return oa - ob;
        return a.mac < b.mac ? -1 : (a.mac > b.mac ? 1 : 0);
    });

    macBody.innerHTML = sorted.map(m => {
        const isSelf = m.origin === 'self';
        const rowCls = isSelf ? 'mac-row--self' : 'mac-row--lan';
        const originCls = isSelf ? 'mac-origin--self' : 'mac-origin--lan';
        const originTxt = isSelf ? t('mac_origin_self') : t('mac_origin_lan');
        const originTip = isSelf ? t('mac_origin_self_tip') : t('mac_origin_lan_tip');
        let staleCls = '';
        if (typeof m.last_seen_ts === 'number' && nowSec - m.last_seen_ts > STALE_SEC) {
            staleCls = ' mac-row--stale';
        }
        return `<tr class="${rowCls}${staleCls}">` +
            `<td><code class="mac-cell-mac">${escapeHTML(m.mac)}</code></td>` +
            `<td><code class="mac-cell-peer">${escapeHTML(m.peer_id)}</code></td>` +
            `<td><span class="mac-origin ${originCls}" title="${escapeHTML(originTip)}">${escapeHTML(originTxt)}</span></td>` +
            `<td><span class="mac-cell-seen">${escapeHTML(m.last_seen)}</span></td>` +
            `</tr>`;
    }).join('');

    // Per-peer LAN-forwarding warning.
    const byPeer = {};
    macs.forEach(m => {
        if (!byPeer[m.peer_id]) byPeer[m.peer_id] = { self: 0, lan: 0 };
        if (m.origin === 'self') byPeer[m.peer_id].self++; else byPeer[m.peer_id].lan++;
    });
    const frag = document.createDocumentFragment();
    Object.keys(byPeer).forEach(pid => {
        const info = byPeer[pid];
        if (info.lan >= 2) {
            const short = pid.length > 12 ? pid.slice(0, 10) + "…" : pid;
            const banner = document.createElement('div');
            banner.className = 'mac-warn-banner';
            const ico = document.createElement('span');
            ico.className = 'mac-warn-ico';
            ico.textContent = '⚠';
            const txt = document.createElement('span');
            txt.textContent = t('mac_lan_warn').replace('{peer}', short).replace('{n}', String(info.lan));
            banner.appendChild(ico);
            banner.appendChild(txt);
            frag.appendChild(banner);
        }
    });
    if (frag.childNodes.length) {
        warnWrap.replaceChildren(frag);
        warnWrap.hidden = false;
    } else {
        warnWrap.replaceChildren();
        warnWrap.hidden = true;
    }
};

// (Pending Authorization, or no usable gateway IP) are rendered with the
// `is-pending` class so CSS grays them out and the toggle action is omitted.
window.renderSubnetList = function(subnetListEl, subnets) {
    subnetListEl.replaceChildren();
    if (!subnets || subnets.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'subnet-empty';
        empty.setAttribute('data-i18n', 'no_subnets');
        empty.textContent = t('no_subnets');
        subnetListEl.appendChild(empty);
        return;
    }
    const frag = document.createDocumentFragment();
    subnets.forEach((s, i) => frag.appendChild(buildSubnetRow(s, i + 1)));
    subnetListEl.appendChild(frag);
};

// Render the Duplicate IP / Subnet Conflicts list. Pure DOM builder (no innerHTML,
// no inline styles) so all visual rules live in styles.css under `.dup-*` classes.
window.renderDupConflicts = function(el, conflicts) {
    el.replaceChildren();
    if (!conflicts || conflicts.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'ext52';
        empty.setAttribute('data-i18n', 'no_dup_ip_conflicts');
        empty.textContent = t('no_dup_ip_conflicts');
        el.appendChild(empty);
        return;
    }
    const frag = document.createDocumentFragment();
    conflicts.forEach((c) => frag.appendChild(buildDupConflictRow(c)));
    el.appendChild(frag);
};

// Build a single conflict row: type + resource (head), winner → loser verdict,
// and the arbitration reason.
window.buildDupConflictRow = function(c) {
    const row = document.createElement('div');
    row.className = 'dup-conflict-row';

    const head = document.createElement('div');
    head.className = 'dup-conflict-head';
    const type = document.createElement('span');
    type.className = 'dup-conflict-type';
    type.textContent = c.resource_type || 'conflict';
    const res = document.createElement('span');
    res.className = 'dup-conflict-res';
    res.textContent = c.resource || '-';
    head.appendChild(type);
    head.appendChild(res);
    row.appendChild(head);

    const verdict = document.createElement('div');
    verdict.className = 'dup-conflict-verdict';
    const label = document.createElement('span');
    label.className = 'dup-verdict-label';
    label.textContent = t('dup_winner') + ':';
    const winner = document.createElement('span');
    winner.className = 'dup-winner';
    winner.textContent = c.winner || '-';
    verdict.appendChild(label);
    verdict.appendChild(winner);
    if (c.losers && c.losers.length) {
        const arrow = document.createElement('span');
        arrow.className = 'dup-arrow';
        arrow.textContent = '→';
        const loser = document.createElement('span');
        loser.className = 'dup-loser';
        loser.textContent = c.losers.join(', ');
        verdict.appendChild(arrow);
        verdict.appendChild(loser);
    }
    row.appendChild(verdict);

    if (c.reason) {
        const reason = document.createElement('div');
        reason.className = 'dup-conflict-reason';
        reason.textContent = c.reason;
        row.appendChild(reason);
    }
    return row;
};

// Build a single subnet row. Pure DOM builder (no innerHTML strings),
// so all visual rules live in styles.css under `.subnet-row*` classes.
window.buildSubnetRow = function(s, idx) {
    // Pick the best gateway IP (v6 when the subnet is v6 and we have one,
    // otherwise fall back through v4 → '-'.).
    const isV6Subnet = s.subnet_cidr && s.subnet_cidr.includes(':');
    let gw = s.gateway_ip;
    if (isV6Subnet && s.gateway_ipv6 && s.gateway_ipv6 !== '-') {
        gw = s.gateway_ipv6;
    } else if (!gw || gw === '-') {
        gw = s.gateway_ipv6 || '-';
    }
    const gwIsV6 = gw && gw.includes(':');

    const isDisabled = s.disabled || (s.status && s.status.includes('Disabled'));
    // A route is "non-operable" when it can never be installed in the local
    // routing table — Pending Authorization (peer not in AllowedSubnetPeers)
    // OR no usable gateway IP. These rows must be greyed out and unclickable.
    const isPendingAuth = s.status && s.status.includes('Pending Authorization');
    const hasNoGateway = !gw || gw === '-';
    const isNonOp = isPendingAuth || hasNoGateway;
    const isRoutable = !isNonOp;

    const row = document.createElement('div');
    row.className = 'subnet-row'
        + (isDisabled ? ' is-disabled' : '')
        + (isPendingAuth ? ' is-pending' : '')
        + (hasNoGateway && !isPendingAuth ? ' is-no-gateway' : '')
        + (isRoutable && !isDisabled ? ' is-routable' : '');

    // Left side: index, CIDR pill, via-info row.
    const left = document.createElement('div');
    left.className = 'subnet-left';

    const indexEl = document.createElement('span');
    indexEl.className = 'subnet-num';
    indexEl.textContent = String(idx);
    left.appendChild(indexEl);

    const cidrEl = document.createElement('span');
    cidrEl.className = 'subnet-cidr';
    cidrEl.textContent = s.subnet_cidr || '-';
    left.appendChild(cidrEl);

    const viaEl = document.createElement('div');
    viaEl.className = 'subnet-via';

    const viaLabel = document.createElement('span');
    viaLabel.className = 'subnet-via-label';
    viaLabel.textContent = 'via';
    viaEl.appendChild(viaLabel);

    const nodeName = document.createElement('strong');
    nodeName.className = 'subnet-node';
    nodeName.textContent = s.node_name || '-';
    viaEl.appendChild(nodeName);

    if (gw && gw !== '-') {
        const gwPill = document.createElement('span');
        gwPill.className = 'subnet-gw-pill' + (gwIsV6 ? ' is-v6' : ' is-v4');
        // Expose the full IP on hover so even on narrow viewports (where the
        // pill's text-overflow:ellipsis might still clip IPv6) the user can
        // always read the gateway by hovering.
        gwPill.title = gw;
        gwPill.textContent = gw;
        viaEl.appendChild(gwPill);
    }
    left.appendChild(viaEl);
    row.appendChild(left);

    // Right side: status badge + (optional) enable/disable toggle.
    const right = document.createElement('div');
    right.className = 'subnet-right';

    const statusEl = document.createElement('span');
    if (isPendingAuth) {
        statusEl.className = 'subnet-status is-pending';
        statusEl.textContent = t('badge_subnet_pending');
    } else if (isDisabled) {
        statusEl.className = 'subnet-status is-disabled';
        statusEl.textContent = t('badge_subnet_disabled');
    } else {
        statusEl.className = 'subnet-status is-authorized';
        statusEl.textContent = s.status || '-';
    }
    right.appendChild(statusEl);

    if (isRoutable) {
        // iOS-style toggle: <label> wraps a hidden checkbox + a visual track.
        // Click anywhere on the label → checkbox toggles → change event fires
        // → toggleSubnetRoute(cidr, !isDisabled) is invoked.
        const lbl = document.createElement('label');
        lbl.className = 'subnet-switch' + (isDisabled ? ' is-off' : ' is-on');

        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'subnet-switch-input';
        cb.checked = !isDisabled;
        cb.setAttribute('aria-label',
            isDisabled ? t('btn_enable_subnet') : t('btn_disable_subnet'));
        cb.addEventListener('change', () => {
            // change fires AFTER the browser flips the checkbox, so cb.checked
            // is already the NEW desired state — forward it directly. (The
            // previous `!cb.checked` inverted intent, making every click a no-op
            // and snapping the UI back on the next fetchStats render.)
            toggleSubnetRoute(s.subnet_cidr, cb.checked);
        });
        lbl.appendChild(cb);

        const track = document.createElement('span');
        track.className = 'subnet-switch-track';
        const slider = document.createElement('span');
        slider.className = 'subnet-switch-slider';
        track.appendChild(slider);
        lbl.appendChild(track);

        right.appendChild(lbl);
    } else {
        const noop = document.createElement('span');
        noop.className = 'subnet-noop';
        noop.textContent = hasNoGateway ? '—' : t('subnet_no_toggle');
        right.appendChild(noop);
    }
    row.appendChild(right);

    return row;
};

window.toggleSubnetRoute = async function(cidr, enable) {
            const boolEnable = (enable === true || enable === 'true');
            try {
                const resp = await fetch('/api/subnet/toggle', withAuth({
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ cidr: cidr, enable: boolEnable })
                }));
                const res = await resp.json();
                if (res.status === 'ok') {
                    const msg = boolEnable ? t('toast_subnet_enabled').replace('{cidr}', cidr) : t('toast_subnet_disabled').replace('{cidr}', cidr);
                    showToast(msg, false);
                    fetchStats();
                } else {
                    showToast('❌ ' + (res.error || 'Operation failed'), true);
                }
            } catch(e) {
                console.error('Toggle subnet error:', e);
                showToast('❌ ' + e.message, true);
            }
        };

        async function testSingleMultiaddrEcho(peerID, multiaddr) {
            showToast(t('probing_echo').replace('{addr}', multiaddr), false);
            try {
                const res = await fetch('/api/peer/echo', withAuth({
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        peer_id: peerID,
                        multiaddr: multiaddr
                    })
                }));
                const json = await res.json();
                if (json && json.success) {
                    const rttMs = json.rtt_ms !== undefined ? json.rtt_ms.toFixed(2) : 'N/A';
                    const rttUs = json.rtt_us !== undefined ? json.rtt_us : 'N/A';
                    const actualPath = json.transport_addr ? ` via ${json.transport_addr}` : '';
                    showToast(`⚡ Echo SUCCESS! RTT: ${rttMs} ms (${rttUs} µs)${actualPath} [32B Verified]`, false);
                } else {
                    showToast(`❌ Echo probe failed: ${json.error || 'Stream failed'}`, true);
                }
            } catch(e) {
                showToast(`❌ Echo request error: ${e.message}`, true);
            }
        }

        // --- Live Terminal Log Stream Engine ---
        let currentLogFilter = localStorage.getItem('p2ptap_log_filter') || 'ALL';
        let isAutoScroll = localStorage.getItem('p2ptap_log_autoscroll') !== 'false';
        let logsPaused = localStorage.getItem('p2ptap_log_paused') === 'true';

        function updateLogFilterUI() {
            document.querySelectorAll('.filter-btn').forEach(btn => {
                const lvl = btn.getAttribute('data-level') || btn.innerText.trim();
                btn.classList.toggle('active', lvl === currentLogFilter);
            });
            const btn = document.getElementById('autoScrollBtn');
            if (btn) {
                btn.innerText = isAutoScroll ? (t('auto_scroll') || '📜 Auto-Scroll: ON') : (t('auto_scroll_off') || '📜 Auto-Scroll: OFF');
            }
        }

        function escapeHTML(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        // attrStr() returns an HTML-encoded JS string literal for safe use inside
        // a double-quoted HTML attribute (e.g. data-onclick="foo(${attrStr(x)})").
        //
        // Critical: we must emit HTML entities (&quot;) — NOT JS escape sequences
        // (\") — because the browser's HTML parser scans the attribute value
        // for the closing '"' BEFORE any JS evaluation. Emitting a raw '"' (or
        // even a backslash-escaped \") inside an attribute still terminates the
        // attribute at the first '"'. Only &quot; is decoded to '"' AFTER the
        // attribute is closed, so it survives HTML parsing and is then evaluated
        // as a proper JS string literal by the click handler.
        function attrStr(s) {
            if (s === undefined || s === null) return '&quot;&quot;';
            return '&quot;' + String(s)
                .replace(/&/g, '&amp;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/\n/g, '&#10;')
                .replace(/\r/g, '&#13;')
                .replace(/\t/g, '&#9;')
                + '&quot;';
        }

        // --- Live rendering helpers (shared by WebSocket stream + HTTP fallback) ---
        let logLiveTotal = 0;   // raw entries seen (matching or not)
        let logLiveShown = 0;   // entries currently displayed (pass the filter)

        function logMatchesFilter(l) {
            return currentLogFilter === 'ALL' || (l.level && l.level.toUpperCase() === currentLogFilter.toUpperCase());
        }

        function logLineHTML(l) {
            const lvl = (l.level || 'INFO').toUpperCase();
            const mod = escapeHTML(l.module || 'System');
            const msg = escapeHTML(l.message || '');
            const time = escapeHTML(l.timestamp || '');
            return `
                        <div class="log-line ${lvl}">
                            <span class="log-time">${time}</span>
                            <span class="log-tag ${lvl}">[${lvl}]</span>
                            <span class="log-mod">[${mod}]</span>
                            <span class="log-msg">${msg}</span>
                        </div>
                    `;
        }

        // updateLogCountBadge reflects what the user actually sees. When a
        // non-ALL filter excludes entries we still surface the raw ring size as
        // a parenthetical so the operator doesn't lose the "buffer holds N
        // entries" signal — but the primary number is strictly the displayed
        // count.
        function updateLogCountBadge(shown, total) {
            const countBadge = document.getElementById('logCountBadge');
            if (!countBadge) return;
            const base = t('log_count').replace('{n}', shown);
            countBadge.innerText = (currentLogFilter !== 'ALL' && total !== undefined && total !== shown)
                ? `${base} (${total})`
                : base;
        }

        // renderLogBacklog does a full (re)render of a batch of entries — used
        // for the initial WebSocket backlog and for a full refresh triggered by
        // a filter change / pause-resume / HTTP fallback poll.
        function renderLogBacklog(entries) {
            const box = document.getElementById('terminalBox');
            if (!box || !Array.isArray(entries)) return;
            const filtered = entries.filter(logMatchesFilter);
            logLiveTotal = entries.length;
            logLiveShown = filtered.length;
            updateLogCountBadge(logLiveShown, logLiveTotal);

            if (filtered.length === 0) {
                box.innerHTML = '<div style="color:var(--text-muted); font-style:italic; padding:8px;">No log entries match the selected filter.</div>';
                return;
            }
            // Save scroll position to avoid jump-to-top on re-render.
            const savedScrollTop = isAutoScroll ? box.scrollHeight : box.scrollTop;
            box.innerHTML = filtered.map(logLineHTML).join('');
            box.scrollTop = isAutoScroll ? box.scrollHeight : savedScrollTop;
        }

        // appendLogEntry adds a single new line to the live view (respecting the
        // filter and the auto-scroll / pause state). Returns true if appended.
        function appendLogEntry(entry) {
            if (!entry) return false;
            logLiveTotal++;
            if (!logMatchesFilter(entry)) return false;
            const box = document.getElementById('terminalBox');
            if (!box) return false;
            // If the box currently shows the "no matches" placeholder, clear it
            // before appending real lines.
            if (box.children.length === 1 && box.firstElementChild && box.firstElementChild.getAttribute('style') && box.firstElementChild.getAttribute('style').indexOf('font-style:italic') !== -1) {
                box.innerHTML = '';
            }
            const atBottom = isAutoScroll || (box.scrollHeight - box.scrollTop - box.clientHeight) < 40;
            box.insertAdjacentHTML('beforeend', logLineHTML(entry));
            logLiveShown++;
            updateLogCountBadge(logLiveShown, logLiveTotal);
            if (atBottom) box.scrollTop = box.scrollHeight;
            return true;
        }

        // clearLogView empties the terminal and resets the live counters. Used by
        // both the local Clear button and the server's "cleared" broadcast.
        function clearLogView() {
            const box = document.getElementById('terminalBox');
            if (box) box.innerHTML = '<div style="color:var(--text-muted); font-style:italic; padding:8px;">' + t('logs_cleared') + '</div>';
            logLiveTotal = 0;
            logLiveShown = 0;
            updateLogCountBadge(0, 0);
        }

        let isFetchingLogs = false;
        async function fetchLogs() {
            if (isFetchingLogs) return;
            if (logsPaused) return;
            if (document.hidden) return;
            isFetchingLogs = true;
            try {
                const res = await fetchWithTimeout('/api/logs', {}, 4000);
                if (!res.ok) return;
                const logs = await res.json();
                if (!Array.isArray(logs)) return;
                renderLogBacklog(logs);
            } catch (e) {
                console.error("Fetch logs error:", e);
            } finally {
                isFetchingLogs = false;
            }
        }

        function setLogFilter(lvl) {
            currentLogFilter = lvl;
            localStorage.setItem('p2ptap_log_filter', lvl);
            updateLogFilterUI();
            fetchLogs();
        }

        function toggleAutoScroll() {
            isAutoScroll = !isAutoScroll;
            localStorage.setItem('p2ptap_log_autoscroll', isAutoScroll ? 'true' : 'false');
            updateLogFilterUI();
        }

        function updateLogPauseUI() {
            const btn = document.getElementById('logPauseBtn');
            const badge = document.getElementById('logPausedBadge');
            if (btn) {
                const span = btn.querySelector('span');
                if (span) span.textContent = t(logsPaused ? 'resume_logs' : 'pause_logs');
                btn.classList.toggle('paused-active', logsPaused);
            }
            if (badge) badge.style.display = logsPaused ? 'inline-block' : 'none';
        }

        function toggleLogPause() {
            logsPaused = !logsPaused;
            localStorage.setItem('p2ptap_log_paused', logsPaused ? 'true' : 'false');
            updateLogPauseUI();
            if (!logsPaused) fetchLogs(); // immediately resume streaming on unpause
        }
        window.toggleLogPause = toggleLogPause;

        // --- Terminal resize handle ---
        (function() {
            const handle = document.getElementById('terminalResizeHandle');
            const box = document.getElementById('terminalBox');
            if (!handle || !box) return;
            let startY, startH, dragging = false;
            handle.addEventListener('mousedown', function(e) {
                e.preventDefault();
                dragging = true;
                startY = e.clientY;
                startH = box.offsetHeight;
                document.body.style.cursor = 'ns-resize';
                document.body.style.userSelect = 'none';
            });
            document.addEventListener('mousemove', function(e) {
                if (!dragging) return;
                const delta = e.clientY - startY;
                let newH = startH + delta;
                newH = Math.max(100, Math.min(newH, window.innerHeight * 0.8));
                box.style.height = newH + 'px';
            });
            document.addEventListener('mouseup', function(e) {
                if (!dragging) return;
                dragging = false;
                document.body.style.cursor = '';
                document.body.style.userSelect = '';
                localStorage.setItem('p2ptap_log_height', box.offsetHeight);
            });
            // restore saved height
            var saved = localStorage.getItem('p2ptap_log_height');
            if (saved) {
                var h = parseInt(saved, 10);
                if (!isNaN(h)) box.style.height = h + 'px';
            }
        })();

        async function clearLogConsole() {
            clearLogView();
            try {
                await fetch('/api/logs', withAuth({ method: 'DELETE' }));
            } catch (e) {
                console.error("Clear logs API error:", e);
            }
        }

        async function copyLogConsole() {
            const box = document.getElementById('terminalBox');
            if (!box) return;
            // Reconstruct plain text from the currently displayed (filtered) log
            // lines so the clipboard reflects exactly what the user sees. Using
            // textContent avoids copying HTML entities/escaping artifacts.
            const lines = Array.from(box.querySelectorAll('.log-line')).map(el => {
                const time = (el.querySelector('.log-time') || {}).textContent || '';
                const tag = (el.querySelector('.log-tag') || {}).textContent || '';
                const mod = (el.querySelector('.log-mod') || {}).textContent || '';
                const msg = (el.querySelector('.log-msg') || {}).textContent || '';
                return [time, tag, mod, msg].filter(Boolean).join(' ').trim();
            }).filter(Boolean);
            if (lines.length === 0) {
                showToast(t('logs_empty_copy') || 'Nothing to copy yet.', true);
                return;
            }
            try {
                await copyToClipboard(lines.join('\n'));
                showToast(t('logs_copied') || '📋 Logs copied to clipboard!');
            } catch (e) {
                console.error("Copy logs error:", e);
                showToast(t('copy_failed') || 'Copy failed.', true);
            }
        }

        // --- SpeedTest Engine ---
        function openSpeedTestModal(targetPeerID) {
            const select = document.getElementById('speedTestPeerSelect');
            if (select) {
                select.innerHTML = '';
                if (cachedPeers.length === 0) {
                    select.innerHTML = '<option value="">' + (t('no_peers') || 'No active peers available') + '</option>';
                } else {
                    cachedPeers.forEach(p => {
                        const name = p.node_name || p.peer_id.substring(0, 10);
                        const selected = (targetPeerID && p.peer_id === targetPeerID) ? 'selected' : '';
                        select.innerHTML += `<option value="${escapeHTML(p.peer_id)}" ${selected}>${escapeHTML(name)} (${escapeHTML(p.tap_ip) || 'No IP'}) - ${p.rtt_ms}ms</option>`;
                    });
                }
            }
            const modal = document.getElementById('speedTestModal');
            if (modal) {
                modal.classList.add('active');
                modal.style.display = 'flex';
            }
        }

        function closeSpeedTestModal() {
            const modal = document.getElementById('speedTestModal');
            if (modal) {
                modal.classList.remove('active');
                modal.style.display = 'none';
            }
        }

        async function runSpeedTest() {
            const peerID = document.getElementById('speedTestPeerSelect').value;
            const btn = document.getElementById('startSpeedTestBtn');
            btn.disabled = true;
            btn.innerText = '⏳ Testing P2P Link...';
            
            let progress = 0;
            const progressInterval = setInterval(() => {
                progress += 5;
                if (progress <= 100) {
                    document.getElementById('speedProgressBar').style.width = progress + '%';
                    document.getElementById('speedGaugeVal').innerText = (Math.random() * 400 + 100).toFixed(1);
                }
            }, 50);

            try {
                const result = await safeFetchJSON(`/api/speedtest?peer_id=${encodeURIComponent(peerID)}`);
                if (!result.ok) {
                    console.warn("SpeedTest request failed:", result.error);
                    clearInterval(progressInterval);
                    document.getElementById('speedProgressBar').style.width = '0%';
                    showToast(result.error || 'SpeedTest request failed', true);
                    return;
                }
                const data = result.data;

                clearInterval(progressInterval);
                document.getElementById('speedProgressBar').style.width = '100%';
                document.getElementById('speedGaugeVal').innerText = data.mbps;
                document.getElementById('stRTTAvg').innerText = data.rtt_avg + ' ms';
                document.getElementById('stJitter').innerText = '±' + data.jitter + ' ms';
                document.getElementById('stQuality').innerText = data.quality_grade;
            } catch (e) {
                console.error("SpeedTest error:", e);
                clearInterval(progressInterval);
                showToast(e.message || 'SpeedTest error', true);
            } finally {
                btn.disabled = false;
                btn.innerText = t('start_test_btn') || '🚀 Start Benchmark Test';
            }
        }

        // --- Universal Clipboard Copy Function (Supports HTTP IP Addresses & HTTPS) ---
        function copyToClipboard(text) {
            if (navigator.clipboard && window.isSecureContext) {
                return navigator.clipboard.writeText(text);
            } else {
                return new Promise((resolve, reject) => {
                    try {
                        const textArea = document.createElement('textarea');
                        textArea.value = text;
                        textArea.style.position = 'fixed';
                        textArea.style.left = '-999999px';
                        textArea.style.top = '-999999px';
                        document.body.appendChild(textArea);
                        textArea.focus();
                        textArea.select();
                        const successful = document.execCommand('copy');
                        document.body.removeChild(textArea);
                        if (successful) resolve();
                        else reject(new Error('execCommand copy failed'));
                    } catch (err) {
                        reject(err);
                    }
                });
            }
        }

        // --- Real Standard QR Code Engine (ISO/IEC 18004 Standard Matrix Generator) ---
        function generateQRCodeSVG(text) {
            // Standard QR Code Matrix Generator with Reed-Solomon Error Correction & Mode 8-bit Byte Encoding
            const qr = QRCodeEncoder.encode(text);
            return qr.toSVG(200, 12);
        }

        // --- QRCodeEncoder Engine implementation ---
        const QRCodeEncoder = (function() {
            const EXP_TABLE = new Uint8Array(256);
            const LOG_TABLE = new Uint8Array(256);
            for (let i = 0, x = 1; i < 256; i++) {
                EXP_TABLE[i] = x;
                LOG_TABLE[x] = i;
                x = (x << 1) ^ (x & 0x80 ? 0x11d : 0);
            }
            function gfMul(x, y) { return (x === 0 || y === 0) ? 0 : EXP_TABLE[(LOG_TABLE[x] + LOG_TABLE[y]) % 255]; }

            function getRSGenPoly(deg) {
                let poly = [1];
                for (let i = 0; i < deg; i++) {
                    const next = new Array(poly.length + 1).fill(0);
                    for (let j = 0; j < poly.length; j++) {
                        next[j] ^= gfMul(poly[j], EXP_TABLE[i]);
                        next[j + 1] ^= poly[j];
                    }
                    poly = next;
                }
                return poly;
            }

            function calcRSRemainder(data, eccLen) {
                const gen = getRSGenPoly(eccLen);
                const res = new Array(data.length + eccLen).fill(0);
                for (let i = 0; i < data.length; i++) res[i] = data[i];
                for (let i = 0; i < data.length; i++) {
                    const coef = res[i];
                    if (coef !== 0) {
                        for (let j = 0; j < gen.length; j++) {
                            res[i + j] ^= gfMul(gen[j], coef);
                        }
                    }
                }
                return res.slice(data.length);
            }

            return {
                encode: function(text) {
                    const utf8 = new TextEncoder().encode(text);
                    let version = 1;
                    const capacities = [0, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271, 321, 367, 425, 458, 520, 586, 644, 718, 792, 858];
                    for (let v = 1; v <= 20; v++) {
                        if (utf8.length <= capacities[v]) { version = v; break; }
                    }
                    const eccLens = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 26, 30, 24, 28, 30, 28, 28];
                    const eccLen = eccLens[version] || 28;
                    const dataCap = capacities[version] || capacities[20];
                    const size = 17 + version * 4;

                    const bits = [];
                    function addBits(val, len) {
                        for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
                    }
                    addBits(0x4, 4); // Byte mode
                    addBits(utf8.length, version < 10 ? 8 : 16);
                    for (let b of utf8) addBits(b, 8);
                    addBits(0, Math.min(4, dataCap * 8 - bits.length));
                    while (bits.length % 8 !== 0) bits.push(0);
                    const padBytes = [0xec, 0x11];
                    let padIdx = 0;
                    while (bits.length < dataCap * 8) {
                        addBits(padBytes[padIdx++ % 2], 8);
                    }

                    const dataBytes = [];
                    for (let i = 0; i < bits.length; i += 8) {
                        let b = 0;
                        for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
                        dataBytes.push(b);
                    }

                    const eccBytes = calcRSRemainder(dataBytes, eccLen);
                    const finalCodewords = dataBytes.concat(eccBytes);

                    const grid = Array.from({ length: size }, () => new Array(size).fill(null));
                    const isReserved = Array.from({ length: size }, () => new Array(size).fill(false));

                    function markReserved(r, c, val) {
                        grid[r][c] = val;
                        isReserved[r][c] = true;
                    }

                    // Finder patterns
                    function drawFinder(row, col) {
                        for (let r = -1; r <= 7; r++) {
                            for (let c = -1; c <= 7; c++) {
                                const nr = row + r, nc = col + c;
                                if (nr < 0 || nr >= size || nc < 0 || nc >= size) continue;
                                const isDark = (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
                                               (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
                                               (r >= 2 && r <= 4 && c >= 2 && c <= 4);
                                markReserved(nr, nc, isDark ? 1 : 0);
                            }
                        }
                    }
                    drawFinder(0, 0);
                    drawFinder(0, size - 7);
                    drawFinder(size - 7, 0);

                    // Timing patterns
                    for (let i = 8; i < size - 8; i++) {
                        if (!isReserved[6][i]) markReserved(6, i, i % 2 === 0 ? 1 : 0);
                        if (!isReserved[i][6]) markReserved(i, 6, i % 2 === 0 ? 1 : 0);
                    }

                    // Alignment pattern for version >= 2
                    if (version >= 2) {
                        const alignPos = size - 7;
                        for (let r = alignPos - 2; r <= alignPos + 2; r++) {
                            for (let c = alignPos - 2; c <= alignPos + 2; c++) {
                                if (!isReserved[r][c]) {
                                    const isDark = Math.max(Math.abs(r - alignPos), Math.abs(c - alignPos)) !== 1;
                                    markReserved(r, c, isDark ? 1 : 0);
                                }
                            }
                        }
                    }

                    // Format info dummy reserve
                    for (let i = 0; i < 9; i++) {
                        if (!isReserved[8][i]) isReserved[8][i] = true;
                        if (!isReserved[i][8]) isReserved[i][8] = true;
                        if (!isReserved[8][size - 1 - i]) isReserved[8][size - 1 - i] = true;
                        if (!isReserved[size - 1 - i][8]) isReserved[size - 1 - i][8] = true;
                    }
                    markReserved(size - 8, 8, 1);

                    // Place data bits
                    let bitIdx = 0;
                    const allBits = [];
                    for (let byte of finalCodewords) {
                        for (let b = 7; b >= 0; b--) allBits.push((byte >> b) & 1);
                    }

                    let right = size - 1;
                    let upward = true;
                    while (right > 0) {
                        if (right === 6) right--;
                        for (let vertical = 0; vertical < size; vertical++) {
                            const r = upward ? size - 1 - vertical : vertical;
                            for (let colOffset = 0; colOffset < 2; colOffset++) {
                                const c = right - colOffset;
                                if (!isReserved[r][c]) {
                                    const bitVal = bitIdx < allBits.length ? allBits[bitIdx++] : 0;
                                    grid[r][c] = bitVal;
                                }
                            }
                        }
                        upward = !upward;
                        right -= 2;
                    }

                    // Apply mask 0 ((r + c) % 2 === 0)
                    for (let r = 0; r < size; r++) {
                        for (let c = 0; c < size; c++) {
                            if (!isReserved[r][c]) {
                                if ((r + c) % 2 === 0) grid[r][c] ^= 1;
                            }
                        }
                    }

                    // Draw format info (Mask 0 + ECC Level M)
                    const formatBits = [1,0,1,0,1,0,0,0,0,0,1,0,0,1,0];
                    for (let i = 0; i < 6; i++) grid[8][i] = formatBits[i];
                    grid[8][7] = formatBits[6];
                    grid[8][8] = formatBits[7];
                    grid[7][8] = formatBits[8];
                    for (let i = 0; i < 6; i++) grid[5 - i][8] = formatBits[9 + i];
                    for (let i = 0; i < 8; i++) grid[8][size - 1 - i] = formatBits[i];
                    for (let i = 0; i < 7; i++) grid[size - 1 - i][8] = formatBits[8 + i];

                    return {
                        size: size,
                        toSVG: function(pixelSize, margin) {
                            const scale = (pixelSize - margin * 2) / size;
                            let rects = '';
                            for (let r = 0; r < size; r++) {
                                for (let c = 0; c < size; c++) {
                                    if (grid[r][c] === 1) {
                                        rects += `<rect x="${(margin + c * scale).toFixed(2)}" y="${(margin + r * scale).toFixed(2)}" width="${(scale + 0.1).toFixed(2)}" height="${(scale + 0.1).toFixed(2)}" fill="#0f172a"/>`;
                                    }
                                }
                            }
                            return `<svg xmlns="http://www.w3.org/2000/svg" width="${pixelSize}" height="${pixelSize}" viewBox="0 0 ${pixelSize} ${pixelSize}"><rect width="100%" height="100%" fill="#ffffff"/>${rects}</svg>`;
                        }
                    };
                }
            };
        })();

        async function openShareModal() {
            if (!currentFullConfig || Object.keys(currentFullConfig).length === 0) {
                try {
                    const res = await fetch('/api/config', withAuth());
                    if (res.ok) currentFullConfig = await res.json();
                } catch (e) {
                    console.error("Fetch config error for share modal:", e);
                }
            }
            const container = document.getElementById('qrCodeContainer');
            if (container) {
                const shareData = JSON.stringify((currentFullConfig && Object.keys(currentFullConfig).length > 0) ? currentFullConfig : { node_name: localNodeInfo.name || 'P2P TAP Node', tap_ip: localNodeInfo.ip || '10.0.0.1' }, null, 2);
                container.innerHTML = generateQRCodeSVG(shareData);
            }
            const modal = document.getElementById('shareModal');
            if (modal) {
                modal.classList.add('active');
                modal.style.display = 'flex';
            }
        }

        function closeShareModal() {
            const modal = document.getElementById('shareModal');
            if (modal) {
                modal.classList.remove('active');
                modal.style.display = 'none';
            }
        }

        function copyConfigJSON() {
            const shareData = JSON.stringify((currentFullConfig && Object.keys(currentFullConfig).length > 0) ? currentFullConfig : { node_name: localNodeInfo.name || 'P2P TAP Node', tap_ip: localNodeInfo.ip || '10.0.0.1' }, null, 2);
            copyToClipboard(shareData).then(() => {
                showToast(t('copied_toast') || '📋 Config JSON copied to clipboard!');
            }).catch(err => {
                console.error("Clipboard copy failed:", err);
                showToast('❌ Copy failed: ' + err.message);
            });
        }

        function downloadConfigJSON() {
            const shareData = JSON.stringify((currentFullConfig && Object.keys(currentFullConfig).length > 0) ? currentFullConfig : { node_name: localNodeInfo.name || 'P2P TAP Node', tap_ip: localNodeInfo.ip || '10.0.0.1' }, null, 2);
            const blob = new Blob([shareData], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'p2ptap-config.json';
            a.click();
            URL.revokeObjectURL(url);
        }

        // --- 🗺️ Interactive P2P Topology Mesh Engine (Drag | Zoom | Double-Click Ping | Particles) ---
        let topoZoom = 1.0;
        let topoPanX = 0;
        let topoPanY = 0;
        let nodeCustomPositions = {};
        let topoUserInteracted = false; // once the user zooms/pans, stop auto-fitting
        let topoFittedSig = '';          // signature of the topology we last auto-fit
        let isTopoDragging = false;
        let isTopoPanning = false;
        let dragNodeId = null;
        let lastMouseX = 0;
        let lastMouseY = 0;
        let topoAnimFrame = null;
        // --- Perf: idle throttle + caches ---
        let topoNeedsRedraw = true;        // force a redraw on next frame (data/interaction/theme)
        let topoLastScheduled = 0;         // timestamp of the last actual draw
        let topoLastTheme = null;          // detect theme flip while idle (so we repaint)
        let topoIndexRef = null;           // cache key for the id->node index
        let topoNodeByID = {};             // cached id->node map; rebuilt only when nodes change
        // --- Selection + filter (interaction) ---
        let topoSelectedId = null;
        let topoSelectedPathSet = new Set();   // node ids on the selected path to self
        let topoSelectedEdgeSet = new Set();   // "parent|child" pairs on that path
        let topoFilterMode = 'all';            // 'all' | 'direct' | 'relayed'
        let topoDragMoved = false;             // distinguish a click from a drag/pan
        const topoTextCache = new Map();   // font\u0000text -> measured width (avoids per-frame measureText)
        function topoMeasure(ctx, font, text) {
            const key = font + '\u0000' + text;
            let w = topoTextCache.get(key);
            if (w === undefined) {
                ctx.font = font;
                w = ctx.measureText(text).width;
                if (topoTextCache.size > 4000) topoTextCache.clear();
                topoTextCache.set(key, w);
            }
            return w;
        }
        function topoRebuildIndex(nodes) {
            if (topoIndexRef === nodes) return topoNodeByID;
            topoIndexRef = nodes;
            topoNodeByID = {};
            nodes.forEach(n => { topoNodeByID[n.id] = n; });
            return topoNodeByID;
        }
        // Lighten a #rrggbb hex toward white by `amt` (0..1) for gradient highlights.
        function lightenHex(hex, amt) {
            const h = hex.replace('#', '');
            const r = parseInt(h.substring(0, 2), 16);
            const g = parseInt(h.substring(2, 4), 16);
            const b = parseInt(h.substring(4, 6), 16);
            const mix = (c) => Math.round(c + (255 - c) * amt);
            return `rgb(${mix(r)},${mix(g)},${mix(b)})`;
        }

        // Build the hover / pinned-detail HTML for a topology node. Shared by
        // the floating tooltip and the click-to-inspect detail panel so the two
        // never diverge.
        function buildTopoTooltipHTML(found) {
            // Resolve a cluster id → human name, and a relay peer id → name.
            const clusterNameOf = (cid) => {
                if (!cid || !latestTopologyData || !Array.isArray(latestTopologyData.clusters)) return cid || '';
                const c = latestTopologyData.clusters.find(c => c.boot_id === cid);
                return c ? (c.boot_name || c.boot_id) : cid;
            };
            const relayNameOf = (rid) => {
                if (!rid) return '';
                const nn = (window.latestTopoNodes || []).find(x => x.id === rid);
                return nn ? nn.name : ('…' + rid.slice(-6));
            };
            if (found.isSelf) {
                const gwPkts = (latestStatsData && latestStatsData.gateway_packets && latestStatsData.gateway_packets.gateway) || 0;
                return `<div class="tt-title"><span>💻 ${escapeHTML(found.name)}</span><span class="pill-badge role-static" style="font-size:0.7rem;padding:2px 8px;">${t('topo_tt_local_host')}</span></div>`
                    + `<div class="tt-row"><span>${t('topo_tt_ipv4')}</span><span class="tt-val">${escapeHTML(found.tapIP || '-')}</span></div>`
                    + `<div class="tt-row"><span>${t('topo_tt_ipv6')}</span><span class="tt-val">${escapeHTML(found.tapIPv6 || '-')}</span></div>`
                    + (found.isExitServer ? `<div class="tt-row"><span>${t('topo_tt_enc')}</span><span class="tt-val" style="color:var(--warn);">🚪 ${t('topo_badge_exit_server')}</span></div>` : '')
                    + (found.transitCount > 0 ? `<div class="tt-row"><span>${t('topo_tt_route')}</span><span class="tt-val" style="color:var(--warn);">🌉 ${t('topo_badge_transit')} ×${found.transitCount}</span></div>` : '')
                    + (found.totalTx > 0 || found.totalRx > 0 ? `<div class="tt-row"><span>${t('topo_summary_thru')}</span><span class="tt-val" style="color:var(--info);">⬆ ${formatSpeed(found.totalTx || 0)} ⬇ ${formatSpeed(found.totalRx || 0)}</span></div>` : '')
                    + `<div class="tt-row"><span>${t('topo_summary_gw')}</span><span class="tt-val" style="color:var(--accent-purple);">${gwPkts}</span></div>`
                    + (found.cluster ? `<div class="tt-row"><span>${t('topo_tt_cluster')}</span><span class="tt-val" style="color:var(--accent-purple)">${escapeHTML(clusterNameOf(found.cluster))}</span></div>` : '')
                    + `<div class="tt-row"><span>${t('topo_tt_peer_id')}</span><span class="tt-val tt-val-id">${escapeHTML(localNodeInfo.peerID || '-')}</span></div>`;
            }
            const p = found.peer || {};
            const roleClass = p.role === 'Bootstrap' ? 'role-bootstrap' : (p.role === 'Static' ? 'role-static' : 'role-peer');
            const roleIcon = p.role === 'Bootstrap' ? '🟣' : (p.role === 'Static' ? '🟦' : '🟢');
            const roleText = p.role === 'Bootstrap' ? t('topo_badge_boot') : (p.role === 'Static' ? t('topo_badge_static') : (t('topo_badge_peer') || escapeHTML(p.role || 'Peer')));
            const nodeTitle = (p.node_name && p.node_name.trim()) ? escapeHTML(p.node_name) : escapeHTML(found.name);
            const tapIPs = [p.tap_ip, p.tap_ipv6].filter(Boolean).join(' / ') || '-';
            const rttColor = (p.rtt_ms || 0) < 50 ? '#34d399' : '#fbbf24';

            // Encryption / connection-state / path summaries for the tooltip.
            const encAlgo = p.obf_algo || 'none';
            const encColor = (p.obf_encrypted) ? '#34d399' : (encAlgo === 'none' ? '#94a3b8' : '#fbbf24');
            const encTxt = p.obf_encrypted ? encAlgo : (encAlgo === 'none' ? '明文 (none)' : encAlgo + ' 未启用');
            const encHtml = `<div class="tt-row"><span>${t('topo_tt_enc')}</span><span class="tt-val" style="color:${encColor}">${encTxt}</span></div>`;
            const connState = p.conn_state || 'unknown';
            const connColor = (connState === 'ok' || connState === 'relay_ok') ? '#34d399' : (connState === 'connecting' ? '#38bdf8' : '#f87171');
            const connHtml = `<div class="tt-row"><span>${t('topo_tt_conn')}</span><span class="tt-val" style="color:${connColor}">${escapeHTML(connState)}</span></div>`;
            // Return-path liveness (asymmetric routing): shown right next to the
            // outbound connection verdict so the operator sees when they disagree.
            const rpState = p.return_path || 'idle';
            const rpColor = rpState === 'ok' ? '#34d399' : (rpState === 'dead' ? '#f87171' : '#94a3b8');
            const rpHtml = `<div class="tt-row"><span>${t('col_return_path')}</span><span class="tt-val" style="color:${rpColor}" title="${escapeHTML(p.return_path_detail || '')}">${escapeHTML(t('return_' + rpState))}</span></div>`;
            const pathHtml = (found.relayPathNames && found.relayPathNames.length > 0)
                ? `<div class="tt-row"><span>${t('topo_tt_route_via')}</span><span class="tt-val" style="color:var(--warn);">${t('topo_via')} ${escapeHTML(found.relayPathNames.join(' ➔ '))}</span></div>`
                : '';

            const matchedRoute = cachedRoutes.find(r => r.dest_peer === p.peer_id);
            let routeHtml = `<div class="tt-row"><span>${t('topo_tt_route')}</span><span class="tt-val" style="color:var(--success);">🟢 ${t('topo_tt_direct_link')}</span></div>`;
            if (found.isRelayed) {
                routeHtml = `<div class="tt-row"><span>${t('topo_tt_route')}</span><span class="tt-val" style="color:var(--warn);">🔀 ${t('topo_tt_circuit_relay')}</span></div>`;
            } else if (matchedRoute && !matchedRoute.is_direct) {
                routeHtml = `<div class="tt-row"><span>${t('topo_tt_optimal_route')}</span><span class="tt-val" style="color:var(--accent-purple);">🔀 ${escapeHTML(matchedRoute.path_names.join(' ➔ '))}</span></div>`
                    + `<div class="tt-row"><span>${t('topo_tt_route_gain')}</span><span class="tt-val" style="color:var(--success);">⚡ -${matchedRoute.saved_rtt_ms} ms</span></div>`;
            }

            const isTransit = transitRelaySet.has(p.peer_id);
            const transitBadge = isTransit ? `<span class="pill-badge role-bootstrap" style="font-size:0.7rem;padding:2px 8px;margin-left:4px;">🔀 ${t('topo_tt_transit_relay')}</span>` : '';

            // Per-link sequence / link-integrity section.
            const txSeq = found.txSeq || 0, rxSeq = found.rxSeq || 0;
            const dup = found.dedupDrops || 0;
            const winMax = found.seqWinMax || 0;
            const skew = winMax > 0 ? (winMax - rxSeq) : 0;
            const linkBroken = skew >= 1024 || (dup > 0 && rxSeq < winMax);
            const seqColor = linkBroken ? '#f87171' : '#34d399';
            const seqHtml = `<div class="tt-row"><span>${t('topo_tt_seq')}</span><span class="tt-val" style="color:${seqColor}">↑${txSeq} / ↓${rxSeq}</span></div>`
                + (winMax > 0 ? `<div class="tt-row"><span>${t('topo_tt_dedup_window')}</span><span class="tt-val" style="color:${skew >= 1024 ? 'var(--danger)' : 'var(--text-secondary)'}">max=${winMax} (skew ${skew})</span></div>` : '')
                + (dup > 0 ? `<div class="tt-row"><span>${t('topo_tt_dup_drops')}</span><span class="tt-val" style="color:var(--danger)">${dup}</span></div>` : '')
                + (linkBroken ? `<div class="tt-row"><span>${t('topo_tt_link_integrity')}</span><span class="tt-val" style="color:var(--danger)">⚠️ ${t('topo_tt_blackhole')}</span></div>` : `<div class="tt-row"><span>${t('topo_tt_link_integrity')}</span><span class="tt-val" style="color:var(--success)">✅ ${t('topo_tt_healthy')}</span></div>`);

            return `<div class="tt-title"><span>${nodeTitle}</span><div><span class="pill-badge ${roleClass}" style="font-size:0.7rem;padding:2px 8px;">${roleIcon} ${roleText}</span>${transitBadge}</div></div>`
                + `<div class="tt-row"><span>${t('topo_tt_os_arch')}</span><span class="tt-val">${escapeHTML(p.os_arch || 'linux')}</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_tap_ip')}</span><span class="tt-val">${escapeHTML(tapIPs)}</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_transport')}</span><span class="tt-val">${escapeHTML(p.transport || 'P2P')}</span></div>`
                + (found.cluster ? `<div class="tt-row"><span>${t('topo_tt_cluster')}</span><span class="tt-val" style="color:var(--accent-purple)">${escapeHTML(clusterNameOf(found.cluster))}</span></div>` : '')
                + (found.bootHops > 0 ? `<div class="tt-row"><span>${t('topo_tt_boot_hops')}</span><span class="tt-val" style="color:var(--accent-cyan)">${found.bootHops}</span></div>` : '')
                + (found.transportPath ? `<div class="tt-row"><span>${t('topo_tt_transport_path')}</span><span class="tt-val">${escapeHTML(found.transportPath)}</span></div>` : '')
                + (found.relayHop ? `<div class="tt-row"><span>${t('topo_tt_relay_hop')}</span><span class="tt-val" style="color:var(--warn)">${escapeHTML(relayNameOf(found.relayHop))}</span></div>` : '')
                + encHtml
                + connHtml
                + rpHtml
                + `<div class="tt-row"><span>${t('topo_tt_rtt')}</span><span class="tt-val" style="color:${rttColor}">${p.rtt_ms || 0} ms</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_jitter')}</span><span class="tt-val">${(p.jitter_ms || 0).toFixed(1)} ms</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_loss')}</span><span class="tt-val" style="color:${(p.loss_rate_percent || 0) > 1 ? 'var(--danger)' : 'var(--text-secondary)'}">${(p.loss_rate_percent || 0).toFixed(1)}%</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_live_rate')}</span><span class="tt-val" style="color:var(--success);">⬆️ ${formatSpeed(p.tx_speed || 0)} | ⬇️ ${formatSpeed(p.rx_speed || 0)}</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_total')}</span><span class="tt-val">⬆ ${formatBytes(p.total_tx || 0)} ⬇ ${formatBytes(p.total_rx || 0)}</span></div>`
                + routeHtml
                + pathHtml
                + `<div class="tt-row"><span>${t('topo_tt_version')}</span><span class="tt-val">${escapeHTML(p.version || '-')}</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_since')}</span><span class="tt-val">${escapeHTML(p.connected_since || '-')}</span></div>`
                + (p.geo_location ? `<div class="tt-row"><span>${t('topo_tt_geo')}</span><span class="tt-val">${escapeHTML(p.geo_location)}</span></div>` : '')
                + seqHtml
                + `<div class="tt-row"><span>${t('topo_tt_uptime')}</span><span class="tt-val">${escapeHTML(p.uptime || '-')}</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_peer_id')}</span><span class="tt-val tt-val-id">${escapeHTML(p.peer_id || '-')}</span></div>`;
        }

        // --- Selection + filter (interaction) -------------------------------
        function topoNodeMatchesFilter(n) {
            if (topoFilterMode === 'all') return true;
            if (topoFilterMode === 'direct') return !n.isSelf && !n.isRelayed;
            if (topoFilterMode === 'relayed') return n.isRelayed;
            if (topoFilterMode === 'remote') {
                const localCluster = (latestTopologyData && latestTopologyData.local_cluster) || '';
                return !n.isSelf && !!n.cluster && n.cluster !== localCluster;
            }
            return true;
        }

        function selectTopoNode(id) {
            const nodes = window.latestTopoNodes || [];
            const byID = {};
            nodes.forEach(n => { byID[n.id] = n; });
            const node = byID[id];
            if (!node) return;
            topoSelectedId = id;
            // Walk the parent chain up to self to mark the highlighted path.
            topoSelectedPathSet = new Set();
            topoSelectedEdgeSet = new Set();
            let cur = node, guard = 0;
            while (cur && guard < 128) {
                topoSelectedPathSet.add(cur.id);
                if (cur.parentId && byID[cur.parentId]) {
                    topoSelectedEdgeSet.add(cur.parentId + '|' + cur.id);
                    cur = byID[cur.parentId];
                } else break;
                guard++;
            }
            topoNeedsRedraw = true;
            renderTopoDetailPanel(node);
        }

        function clearTopoSelection() {
            if (topoSelectedId === null) return;
            topoSelectedId = null;
            topoSelectedPathSet = new Set();
            topoSelectedEdgeSet = new Set();
            topoNeedsRedraw = true;
            const p = document.getElementById('topoDetailPanel');
            if (p) { p.style.display = 'none'; p.innerHTML = ''; }
        }

        function selectTopoFilter(mode) {
            topoFilterMode = mode;
            ['all', 'direct', 'relayed', 'remote'].forEach(m => {
                const b = document.getElementById('topoFilter' + m.charAt(0).toUpperCase() + m.slice(1));
                if (b) b.classList.toggle('is-active', m === mode);
            });
            topoNeedsRedraw = true;
        }

        function renderTopoDetailPanel(node) {
            const p = document.getElementById('topoDetailPanel');
            if (!p) return;
            const closeTitle = t('topo_clear_sel') || 'Close';
            const html = buildTopoTooltipHTML(node)
                + `<button class="topo-detail-close" data-onclick="clearTopoSelection()" title="${closeTitle}" aria-label="${closeTitle}">✕</button>`;
            p.innerHTML = html;
            p.style.display = 'block';
        }

        function resetTopologyZoom() {
            topoZoom = 1.0;
            topoPanX = 0;
            topoPanY = 0;
            nodeCustomPositions = {};
            topoUserInteracted = false;
            topoFittedSig = '';
            drawTopologyMesh();
        }

        // Auto-fit the view to the current topology — but only when the set of
        // nodes changed AND the user hasn't manually zoomed/panned yet. This way
        // the enlarged canvas is actually used, while a manual layout persists.
        function autoFitTopologyIfNeeded() {
            const nodes = window.latestTopoNodes;
            if (!nodes || !nodes.length) return;
            const ids = nodes.map(n => n.id).sort().join('|');
            if (topoUserInteracted || ids === topoFittedSig) return;
            topoFittedSig = ids;
            fitTopologyToView();
        }

        // Scale + center the whole mesh so it fills the (now larger) canvas with
        // a small margin. Capped so a tiny mesh isn't blown up grotesquely.
        function fitTopologyToView() {
            const nodes = window.latestTopoNodes;
            if (!nodes || !nodes.length) return;
            const leafNodes = nodes.reduce((a, nn) => a + (nn.isSelf ? 0 : 1), 0);
            let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
            for (const n of nodes) {
                const r = topoNodeRadius(n, leafNodes);
                // Reserve room for the name + (when not crowded) the self label
                // block beneath each node, and the exit marker above.
                minX = Math.min(minX, n.x - r - 12);
                maxX = Math.max(maxX, n.x + r + 12);
                minY = Math.min(minY, n.y - r - 10);
                maxY = Math.max(maxY, n.y + r + (n.isSelf && leafNodes <= 12 ? 52 : 30));
            }
            const bw = Math.max(1, maxX - minX);
            const bh = Math.max(1, maxY - minY);
            let z = Math.min(topoCanvasW / bw, topoCanvasH / bh, 2.2) * 0.96;
            if (!isFinite(z) || z <= 0) z = 1.0;
            z = Math.max(0.25, z);
            topoZoom = z;
            topoPanX = topoCanvasW / 2 - z * (minX + maxX) / 2;
            topoPanY = topoCanvasH / 2 - z * (minY + maxY) / 2;
        }

        function initTopologyCanvasEvents() {
            const container = document.getElementById('topologyContainer');
            const canvas = document.getElementById('topologyCanvas');
            if (!container || !canvas || canvas.getAttribute('data-events-bound')) return;
            canvas.setAttribute('data-events-bound', 'true');

            canvas.addEventListener('wheel', (e) => {
                e.preventDefault();
                topoUserInteracted = true;
                const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
                topoZoom = Math.min(Math.max(0.4, topoZoom * zoomFactor), 3.5);
                drawTopologyMesh();
            }, { passive: false });

            canvas.addEventListener('mousedown', (e) => {
                const rect = canvas.getBoundingClientRect();
                const mouseX = (e.clientX - rect.left - topoPanX) / topoZoom;
                const mouseY = (e.clientY - rect.top - topoPanY) / topoZoom;

                lastMouseX = e.clientX;
                lastMouseY = e.clientY;
                topoDragMoved = false;

                const currentNodes = window.latestTopoNodes || [];
                let hitNode = null;
                for (let n of currentNodes) {
                    const dx = mouseX - n.x;
                    const dy = mouseY - n.y;
                    if (dx * dx + dy * dy <= 25 * 25) {
                        hitNode = n;
                        break;
                    }
                }

                if (hitNode) {
                    isTopoDragging = true;
                    dragNodeId = hitNode.id;
                    container.style.cursor = 'grabbing';
                } else {
                    isTopoPanning = true;
                    container.style.cursor = 'grabbing';
                }
            });

            window.addEventListener('mousemove', (e) => {
                if (!isTopoDragging && !isTopoPanning) return;
                topoUserInteracted = true;
                topoDragMoved = true;
                const dx = e.clientX - lastMouseX;
                const dy = e.clientY - lastMouseY;
                lastMouseX = e.clientX;
                lastMouseY = e.clientY;

                if (isTopoDragging && dragNodeId) {
                    if (!nodeCustomPositions[dragNodeId]) nodeCustomPositions[dragNodeId] = { x: 0, y: 0 };
                    nodeCustomPositions[dragNodeId].x += dx / topoZoom;
                    nodeCustomPositions[dragNodeId].y += dy / topoZoom;
                    drawTopologyMesh();
                } else if (isTopoPanning) {
                    topoPanX += dx;
                    topoPanY += dy;
                    drawTopologyMesh();
                }
            });

            window.addEventListener('mouseup', (e) => {
                const wasDrag = topoDragMoved;
                isTopoDragging = false;
                isTopoPanning = false;
                dragNodeId = null;
                if (container) container.style.cursor = 'grab';
                // A click (no drag/pan) selects the node under the cursor, or
                // clears the selection when clicking empty space.
                if (!wasDrag && e && e.target === canvas) {
                    const rect = canvas.getBoundingClientRect();
                    const mx = (e.clientX - rect.left - topoPanX) / topoZoom;
                    const my = (e.clientY - rect.top - topoPanY) / topoZoom;
                    const cur = window.latestTopoNodes || [];
                    let hit = null;
                    for (const n of cur) {
                        const dx = mx - n.x, dy = my - n.y;
                        if (dx * dx + dy * dy <= 25 * 25) { hit = n; break; }
                    }
                    if (hit) selectTopoNode(hit.id); else clearTopoSelection();
                }
                topoDragMoved = false;
            });

            canvas.addEventListener('dblclick', (e) => {
                const rect = canvas.getBoundingClientRect();
                const mouseX = (e.clientX - rect.left - topoPanX) / topoZoom;
                const mouseY = (e.clientY - rect.top - topoPanY) / topoZoom;

                const currentNodes = window.latestTopoNodes || [];
                for (let n of currentNodes) {
                    const dx = mouseX - n.x;
                    const dy = mouseY - n.y;
                    if (dx * dx + dy * dy <= 25 * 25) {
                        const targetIp = (n.peer && (n.peer.tap_ip || n.peer.peer_id)) || n.id;
                        if (targetIp && targetIp !== 'self') {
                            setPingTarget(targetIp);
                            showToast(`⚡ Double-clicked node: Triggering Ping to ${targetIp}...`, false);
                        }
                        break;
                    }
                }
            });

            // --- Hover / Tooltip for node inspection ---
            let hoveredNodeId = null;

            canvas.addEventListener('mousemove', function topoHover(e) {
                if (isTopoDragging || isTopoPanning) {
                    const tt = document.getElementById('topologyTooltip');
                    if (tt) tt.style.display = 'none';
                    hoveredNodeId = null;
                    return;
                }
                const rect = canvas.getBoundingClientRect();
                const mx = (e.clientX - rect.left - topoPanX) / topoZoom;
                const my = (e.clientY - rect.top - topoPanY) / topoZoom;
                const tt = document.getElementById('topologyTooltip');
                const currentNodes = window.latestTopoNodes || [];

                let found = null;
                for (const n of currentNodes) {
                    const dx = mx - n.x, dy = my - n.y;
                    if (dx * dx + dy * dy <= 24 * 24) { found = n; break; }
                }

                if (!found) {
                    if (tt) tt.style.display = 'none';
                    canvas.style.cursor = 'grab';
                    hoveredNodeId = null;
                    return;
                }

                if (hoveredNodeId === found.id) return; // avoid redraw on same node
                hoveredNodeId = found.id;
                canvas.style.cursor = 'pointer';

                if (!tt) return;
                tt.style.display = 'block';
                const sx = (found.x * topoZoom + topoPanX) + 18;
                const sy = (found.y * topoZoom + topoPanY) - 10;
                tt.style.left = sx + 'px';
                tt.style.top = sy + 'px';
                tt.innerHTML = buildTopoTooltipHTML(found);
            });

            canvas.addEventListener('mouseleave', () => {
                const tt = document.getElementById('topologyTooltip');
                if (tt) tt.style.display = 'none';
                hoveredNodeId = null;
                if (!isTopoDragging && !isTopoPanning) canvas.style.cursor = 'grab';
            });
        }

        // --- P2P Topology Star Chart (@60fps) ----------------------------------
        // The heavy layout (node positions, link colors, canvas sizing) is
        // computed only when data arrives or the user interacts. The actual
        // drawing is driven by a requestAnimationFrame loop (renderTopology)
        // that animates data-flow particles along each link. The particle speed
        // and density are coupled to the REAL per-link byte rate (rxSpeed /
        // txSpeed from /api/stats), so an idle link shows no flow while a busy
        // link flows faster and denser. This is decoupled from the 2s stats
        // polling (advancing a per-peer phase by rate*dt each frame) to keep
        // the canvas smooth at 60fps regardless of polling frequency.

        let topoCanvasW = 0, topoCanvasH = 0, topoDPR = 1;
        let topoRAFId = null;
        let topoLastFrameTs = 0;
        // Per-peer accumulated flow phase (inbound/outbound), advanced each frame
        // by an amount proportional to the REAL per-link byte rate (rxSpeed/
        // txSpeed). This makes the topology "data flow" truthful: idle links do
        // not animate, busy links flow faster and denser. Decoupled from the 2s
        // stats poll so the animation stays smooth at 60fps.
        let topoFlowState = {};
        const TOPO_IDLE_BPS = 1024; // below ~1 KB/s a link is treated as idle (no flow)

        function drawTopologyMesh() { topoNeedsRedraw = true; computeTopologyLayout(); }

        // Truncate long node names so on-canvas labels don't overlap neighbours.
        // The full name is always available in the hover tooltip.
        function topoShortLabel(s) {
            if (!s) return '';
            return s.length > 16 ? s.slice(0, 15) + '…' : s;
        }

        // Node radius shrinks as the mesh grows so the star map keeps more
        // peers on screen without them overlapping. Self stays a touch larger.
        function topoNodeRadius(n, leafCount) {
            let base;
            if (leafCount <= 3) base = n.isSelf ? 22 : 16;
            else if (leafCount <= 8) base = n.isSelf ? 18 : 13;
            else if (leafCount <= 16) base = n.isSelf ? 15 : 10;
            else if (leafCount <= 30) base = n.isSelf ? 13 : 8;
            else base = n.isSelf ? 11 : 6.5;
            return base;
        }


        // Recompute node layout + link colors. Cheap; called on data/interaction.
        function computeTopologyLayout() {
            initTopologyCanvasEvents();
            const canvas = document.getElementById('topologyCanvas');
            if (!canvas) return;
            const container = canvas.parentElement;
            const rect = container.getBoundingClientRect();
            const cssW = rect.width || 800;
            const cssH = rect.height || 340;

            // --- High-DPI Anti-Aliased Retina Resolution Scaling ---
            const dpr = window.devicePixelRatio || 1;
            if (canvas.width !== Math.round(cssW * dpr) || canvas.height !== Math.round(cssH * dpr)) {
                canvas.width = Math.round(cssW * dpr);
                canvas.height = Math.round(cssH * dpr);
                canvas.style.width = cssW + 'px';
                canvas.style.height = cssH + 'px';
            }
            topoCanvasW = cssW;
            topoCanvasH = cssH;
            topoDPR = dpr;

            const centerX = cssW / 2;
            const centerY = cssH / 2;

            // Pull live per-peer stats keyed by peer_id for color/rate merging.
            const liveByID = {};
            const peers = (latestStatsData && Array.isArray(latestStatsData.active_peers)) ? latestStatsData.active_peers : (cachedPeers || []);
            peers.forEach(p => { if (p.peer_id) liveByID[p.peer_id] = p; });

            // --- Hierarchical tree layout (preferred) ---
            // Built from /api/topology: every node carries its parent in the
            // shortest-path tree, so transit relays naturally sit above the peers
            // they carry. Relayed peers hang under the relay that reaches them.
            if (latestTopologyData && Array.isArray(latestTopologyData.nodes) && latestTopologyData.nodes.length > 0) {
                const topoNodes = latestTopologyData.nodes;
                const byID = {};
                topoNodes.forEach(tn => { byID[tn.peer_id] = tn; });

                // Index link-state edge classes (direct | circuit) by an
                // undirected key so mkNode can resolve the line style of the
                // edge from each node up to its parent in the shortest-path tree.
                const edgeClassByKey = new Map();
                (latestTopologyData.edges || []).forEach(e => {
                    edgeClassByKey.set(e.from + '|' + e.to, e.class);
                    edgeClassByKey.set(e.to + '|' + e.from, e.class);
                });

                const selfID = (latestStatsData && latestStatsData.peer_id) || latestTopologyData.local_peer_id || 'self';

                const mkNode = (tn) => {
                    const live = liveByID[tn.peer_id] || {};
                    const rtt = (typeof live.rtt_ms === 'number') ? live.rtt_ms : (tn.rtt || 0);
                    const isRelayed = !tn.direct && !tn.self;
                    const isRelayAny = isRelayed || !!tn.relay; // relayed reach OR transit-relay role
                    const isBoot = !!tn.is_boot;
                    const isStatic = !!tn.static;
                    const cluster = tn.cluster || null;
                    const bootHops = (typeof tn.boot_hops === 'number') ? tn.boot_hops : 0;
                    const transportPath = tn.transport_path || (tn.direct ? 'direct' : '');
                    const relayHop = tn.relay_hop || '';
                    // Resolve the link-state class of the edge from this node up
                    // to its parent (best-effort; SPT parent may not equal graph edge).
                    const pId = (tn.parent && tn.parent !== tn.peer_id) ? tn.parent : (tn.self ? null : selfID);
                    const linkClass = pId ? (edgeClassByKey.get(pId + '|' + tn.peer_id) || '') : '';
                    // Line style: overlay-relay = long dash, circuit-relay /
                    // circuit edge = short dash, otherwise solid direct.
                    let lineStyle = 'solid';
                    if (transportPath === 'overlay-relay') lineStyle = 'overlay';
                    else if (transportPath === 'circuit-relay' || linkClass === 'circuit') lineStyle = 'circuit';
                    let linkColor = "#34d399";
                    if (isRelayAny || rtt > 100) linkColor = "#fbbf24";
                    else if (rtt > 30) linkColor = "#38bdf8";
                    return {
                        id: tn.peer_id,
                        name: tn.node_name || (tn.peer_id ? '...' + tn.peer_id.substring(Math.max(0, tn.peer_id.length - 8)) : 'Peer'),
                        parentId: (tn.parent && tn.parent !== tn.peer_id) ? tn.parent : (tn.self ? null : selfID),
                        depth: tn.depth || 0,
                        isSelf: !!tn.self,
                        isRelay: !!tn.relay,
                        isRelayed: isRelayed,
                        isBoot: isBoot,
                        isStatic: isStatic,
                        cluster: cluster,
                        bootHops: bootHops,
                        transportPath: transportPath,
                        relayHop: relayHop,
                        linkClass: linkClass,
                        lineStyle: lineStyle,
                        rtt: rtt,
                        linkColor: linkColor,
                        particleColor: isRelayAny ? "#f59e0b" : (rtt < 30 ? "#34d399" : "#38bdf8"),
                        glowColor: isRelayAny ? "#fbbf24" : "#38bdf8",
                        role: live.role || (tn.relay ? 'relay' : (isRelayed ? 'relayed' : (isBoot ? 'bootstrap' : 'direct'))),
                        txSeq: (typeof live.tx_seq === 'number') ? live.tx_seq : 0,
                        rxSeq: (typeof live.rx_seq === 'number') ? live.rx_seq : 0,
                        dedupDrops: (typeof live.dedup_drops === 'number') ? live.dedup_drops : 0,
                        seqWinMax: (typeof live.seq_win_max === 'number') ? live.seq_win_max : 0,
                        txSpeed: (typeof live.tx_speed === 'number') ? live.tx_speed : 0,
                        rxSpeed: (typeof live.rx_speed === 'number') ? live.rx_speed : 0,
                        tapIP: tn.tap_ip || (tn.self ? ((latestStatsData && latestStatsData.tap_ip) || localNodeInfo.ip || '') : ''),
                        tapIPv6: tn.tap_ipv6 || '',
                        peer: live
                    };
                };

                const nodes = topoNodes.map(mkNode);
                const nodeByID = {};
                nodes.forEach(n => { nodeByID[n.id] = n; });

                // Merge any live active peers from stats that are not in topology snapshot
                peers.forEach(p => {
                    if (p.peer_id && p.peer_id !== selfID && !nodeByID[p.peer_id]) {
                        const synNode = mkNode({
                            peer_id: p.peer_id,
                            node_name: p.node_name,
                            tap_ip: p.tap_ip,
                            tap_ipv6: p.tap_ipv6,
                            direct: p.role !== 'relayed' && p.role !== 'relay',
                            parent: (p.relay_hop || selfID),
                            depth: 1,
                            is_boot: p.role === 'bootstrap'
                        });
                        nodes.push(synNode);
                        nodeByID[p.peer_id] = synNode;
                    }
                });


                // self node: use display name from stats.
                const selfNode = nodeByID[selfID] || nodes[0];
                if (selfNode) {
                    selfNode.isSelf = true;
                    selfNode.name = (latestStatsData && latestStatsData.node_name) ? latestStatsData.node_name : (localNodeInfo.name || t('topo_self_node'));
                    selfNode.tapIP = (latestStatsData && latestStatsData.tap_ip) || localNodeInfo.ip || '';
                    selfNode.tapIPv6 = (latestStatsData && latestStatsData.tap_ipv6) || localNodeInfo.ipv6 || '';
                    selfNode.parentId = null;
                    selfNode.depth = 0;
                    selfNode.cluster = (latestTopologyData && latestTopologyData.local_cluster) || null;
                    selfNode.bootHops = 0;
                }

                // --- Derive relay path, self-transit, and exit-server flags ---
                const edgeSet = new Set();
                (latestTopologyData.edges || []).forEach(e => {
                    edgeSet.add(e.from + '|' + e.to);
                    edgeSet.add(e.to + '|' + e.from);
                });
                nodes.forEach(n => {
                    // Walk parent chain up to self to build a human-readable path.
                    const path = [];
                    let cur = n;
                    let guard = 0;
                    while (cur && cur.parentId && guard < 64) {
                        const p = nodeByID[cur.parentId];
                        if (!p || p.isSelf) break;
                        path.push(p.name || p.id);
                        cur = p;
                        guard++;
                    }
                    n.relayPathNames = path; // names from immediate parent up to (not incl.) self
                    n.hops = path.length;
                });
                // Self acts as an L2 switch when two of its direct peers are NOT
                // directly linked to each other — their traffic must traverse self.
                const directPeers = nodes.filter(n => !n.isSelf && n.parentId === selfID);
                const transitSet = new Set();
                for (let i = 0; i < directPeers.length; i++) {
                    for (let j = i + 1; j < directPeers.length; j++) {
                        const a = directPeers[i], b = directPeers[j];
                        if (!edgeSet.has(a.id + '|' + b.id)) { transitSet.add(a.id); transitSet.add(b.id); }
                    }
                }
                const selfTransitCount = transitSet.size;
                const exitNode = (latestStatsData && latestStatsData.exit_node) || null;
                const selfIsExitServer = !!(exitNode && exitNode.enable && exitNode.role !== 'client');
                if (selfNode) {
                    selfNode.transitCount = selfTransitCount;
                    selfNode.isExitServer = selfIsExitServer;
                }

                // Build children map and lay out top-down by subtree width.
                const childrenOf = {};
                nodes.forEach(n => {
                    if (n.parentId && nodeByID[n.parentId]) {
                        (childrenOf[n.parentId] = childrenOf[n.parentId] || []).push(n);
                    }
                });
                // Bigger top margin leaves room for the (multi-line) self label
                // block so it no longer overlaps depth-1 children. A larger
                // bottom reserve keeps leaf labels from being clipped.
                const topMargin = 104;
                const bottomMargin = 88;
                // Floor keeps depth-1 clear of self's label block; a larger mesh
                // still gets proportional spacing from the canvas height.
                const levelGap = Math.max(110, (cssH - topMargin - bottomMargin) / Math.max(1, maxDepth(nodes)));
                const leafTotal = Math.max(1, nodes.length - (selfNode ? 1 : 0));
                // Wider minimum column so even many peers keep legible spacing
                // and their (up-to-16-char) labels never collide horizontally.
                const gapX = Math.max(104, Math.min(220, cssW / leafTotal));
                let leafCursor = 0;
                const assign = (n, depth) => {
                    n.depth = depth;
                    n.baseY = topMargin + depth * levelGap;
                    const kids = childrenOf[n.id] || [];
                    if (kids.length === 0) {
                        n.baseX = (leafCursor + 0.5) * gapX;
                        leafCursor++;
                    } else {
                        kids.forEach(k => assign(k, depth + 1));
                        n.baseX = (kids[0].baseX + kids[kids.length - 1].baseX) / 2;
                    }
                };
                if (selfNode) assign(selfNode, 0);
                // Any orphan nodes (parent missing) get placed at depth 1 under self.
                nodes.forEach(n => {
                    if (n !== selfNode && (!n.parentId || !nodeByID[n.parentId])) {
                        n.parentId = selfNode ? selfNode.id : null;
                        n.baseX = (leafCursor + 0.5) * gapX; leafCursor++;
                        n.baseY = topMargin + levelGap;
                    }
                });

                // --- Same-depth overlap resolution ---------------------------------
                // After the tree layout, push apart any two nodes that share a
                // depth row yet sit closer than a node-diameter + label gutter, so
                // circles and captions never overlap. We then re-center every
                // parent over its (now shifted) children and finally center the
                // whole tree in the canvas.
                const sepMin = 2 * topoNodeRadius({ isSelf: false }, leafTotal) + 72;
                const byDepth = {};
                nodes.forEach(n => { (byDepth[n.depth] = byDepth[n.depth] || []).push(n); });
                Object.keys(byDepth).forEach(d => {
                    const row = byDepth[d].slice().sort((a, b) => a.baseX - b.baseX);
                    for (let i = 1; i < row.length; i++) {
                        if (row[i].baseX - row[i - 1].baseX < sepMin) {
                            row[i].baseX = row[i - 1].baseX + sepMin;
                        }
                    }
                });
                // Re-center each parent over the average x of its children
                // (bottom-up) so edges stay attached after the shift.
                const maxD = maxDepth(nodes);
                for (let d = maxD - 1; d >= 0; d--) {
                    (byDepth[d] || []).forEach(n => {
                        const kids = childrenOf[n.id] || [];
                        if (kids.length) {
                            let sx = 0; kids.forEach(k => { sx += k.baseX; });
                            n.baseX = sx / kids.length;
                        }
                    });
                }

                // Center the whole tree horizontally within the (now larger)
                // canvas instead of anchoring it at the left edge.
                let minBX = Infinity, maxBX = -Infinity;
                nodes.forEach(n => { if (n.baseX < minBX) minBX = n.baseX; if (n.baseX > maxBX) maxBX = n.baseX; });
                if (isFinite(minBX) && isFinite(maxBX) && maxBX > minBX) {
                    const shiftX = (cssW - (maxBX - minBX)) / 2 - minBX;
                    nodes.forEach(n => { n.baseX += shiftX; });
                }

                nodes.forEach(n => {
                    const offset = nodeCustomPositions[n.id] || { x: 0, y: 0 };
                    n.x = n.baseX + offset.x;
                    n.y = n.baseY + offset.y;
                });

                // --- Populate the summary chip bar (glanceable mesh stats) ---
                try {
                    let totalTx = 0, totalRx = 0;
                    nodes.forEach(n => {
                        if (n.isSelf) return;
                        totalTx += (n.txSpeed || 0);
                        totalRx += (n.rxSpeed || 0);
                    });
                    const directCount = directPeers.length;
                    const relayedCount = nodes.filter(n => !n.isSelf && n.isRelayed).length;
                    const relayNodeCount = nodes.filter(n => n.isRelay).length;
                    const bootCount = nodes.filter(n => n.isBoot).length;
                    const staticCount = nodes.filter(n => n.isStatic).length;
                    const clusterCount = (latestTopologyData && Array.isArray(latestTopologyData.clusters)) ? latestTopologyData.clusters.length : 0;
                    const gwPkts = (latestStatsData && latestStatsData.gateway_packets && latestStatsData.gateway_packets.gateway) || 0;
                    if (selfNode) { selfNode.totalTx = totalTx; selfNode.totalRx = totalRx; }
                    const setChip = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
                    setChip('topoSummaryNodes', `🖧 ${nodes.length} ${t('topo_summary_nodes')}`);
                    setChip('topoSummaryDirect', `🟢 ${directCount} ${t('topo_summary_direct')}`);
                    setChip('topoSummaryRelayed', `🟡 ${relayedCount} ${t('topo_summary_relayed')}`);
                    setChip('topoSummaryRelays', `🟠 ${relayNodeCount} ${t('topo_summary_relays')}`);
                    setChip('topoSummaryBoots', `🟣 ${bootCount} ${t('topo_summary_boots')}`);
                    setChip('topoSummaryStatic', `🟦 ${staticCount} ${t('topo_summary_static')}`);
                    setChip('topoSummaryClusters', `▦ ${clusterCount} ${t('topo_summary_clusters')}`);
                    setChip('topoSummaryThru', `⚡ ${t('topo_summary_thru')} ⬆${formatSpeed(totalTx)} ⬇${formatSpeed(totalRx)}`);
                    setChip('topoSummaryGw', `🚪 ${gwPkts} ${t('topo_summary_gw')}`);
                } catch (e) { /* non-fatal */ }

                window.latestTopoNodes = nodes;
                autoFitTopologyIfNeeded();
                return;
            }

            // --- Fallback: star layout from active_peers (legacy behavior) ---
            const nodes = [{
                id: 'self',
                name: (latestStatsData && latestStatsData.node_name) ? latestStatsData.node_name : (localNodeInfo.name || t('topo_self_node')),
                baseX: centerX,
                baseY: centerY,
                isSelf: true,
                tapIP: (latestStatsData && latestStatsData.tap_ip) || localNodeInfo.ip || '',
                tapIPv6: (latestStatsData && latestStatsData.tap_ipv6) || localNodeInfo.ipv6 || ''
            }];

            const radius = Math.min(cssW, cssH) * 0.36;
            const angleStep = (2 * Math.PI) / Math.max(peers.length, 1);

            peers.forEach((p, idx) => {
                const angle = idx * angleStep - Math.PI / 2;
                const rtt = p.rtt_ms || 0;
                const isRelayed = isPeerRelayed(p);
                let linkColor = "#34d399";
                if (isRelayed || rtt > 100) linkColor = "#fbbf24";
                else if (rtt > 30) linkColor = "#38bdf8";
                nodes.push({
                    id: p.peer_id,
                    name: p.node_name || (p.peer_id ? '...' + p.peer_id.substring(p.peer_id.length - 8) : 'Peer'),
                    baseX: centerX + radius * Math.cos(angle),
                    baseY: centerY + radius * Math.sin(angle),
                    parentId: 'self',
                    isRelayed: isRelayed,
                    rtt: rtt,
                    linkColor: linkColor,
                    particleColor: isRelayed ? "#f59e0b" : (rtt < 30 ? "#34d399" : "#38bdf8"),
                    glowColor: isRelayed ? "#fbbf24" : "#38bdf8",
                    role: p.role,
                    txSeq: (typeof p.tx_seq === 'number') ? p.tx_seq : 0,
                    rxSeq: (typeof p.rx_seq === 'number') ? p.rx_seq : 0,
                    dedupDrops: (typeof p.dedup_drops === 'number') ? p.dedup_drops : 0,
                    seqWinMax: (typeof p.seq_win_max === 'number') ? p.seq_win_max : 0,
                    txSpeed: (typeof p.tx_speed === 'number') ? p.tx_speed : 0,
                    rxSpeed: (typeof p.rx_speed === 'number') ? p.rx_speed : 0,
                    peer: p
                });
            });

            nodes.forEach(n => {
                const offset = nodeCustomPositions[n.id] || { x: 0, y: 0 };
                n.x = n.baseX + offset.x;
                n.y = n.baseY + offset.y;
            });
            window.latestTopoNodes = nodes;
            autoFitTopologyIfNeeded();
        }

        function maxDepth(nodes) {
            let m = 0;
            nodes.forEach(n => { if (n.depth > m) m = n.depth; });
            return m;
        }
        function leafCount(nodeByID, childrenOf, rootID) {
            const seen = {};
            const walk = (id) => {
                if (seen[id]) return 0;
                seen[id] = true;
                const kids = childrenOf[id] || [];
                if (kids.length === 0) return 1;
                let c = 0;
                kids.forEach(k => { c += walk(k.id); });
                return c;
            };
            return Math.max(1, walk(rootID));
        }

        // Per-frame renderer, driven by requestAnimationFrame for ~60fps.
        // Build faint bounding hulls that group each boot cluster's members so a
        // multi-cluster / multi-boot mesh reads at a glance. Returns one box per
        // cluster in latestTopologyData.clusters, sized to enclose the boot node
        // (when present) plus all of its member nodes.
        function buildTopoClusterBoxes(nodes, nodeByID) {
            const clusters = (latestTopologyData && Array.isArray(latestTopologyData.clusters)) ? latestTopologyData.clusters : [];
            if (!clusters.length) return [];
            const palette = ['#a855f7', '#06b6d4', '#f59e0b', '#ec4899', '#22c55e', '#3b82f6', '#e11d48', '#14b8a6'];
            const boxes = [];
            clusters.forEach((c, idx) => {
                const pts = [];
                if (nodeByID[c.boot_id]) pts.push(nodeByID[c.boot_id]);
                // The backend serialises `members` as an INTEGER COUNT, NOT an
                // array of peer IDs. Member node POSITIONS must be derived from
                // the live node list (each node carries its owning boot id in
                // `cluster`), so the hull can enclose them.
                const cid = c.boot_id;
                if (cid) {
                    for (let i = 0; i < nodes.length; i++) {
                        const n = nodes[i];
                        if (n.cluster === cid && n.id !== cid) pts.push(n);
                    }
                } else if (Array.isArray(c.members)) {
                    c.members.forEach(mid => { if (nodeByID[mid]) pts.push(nodeByID[mid]); });
                }
                if (pts.length === 0) return;
                let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
                pts.forEach(n => { minX = Math.min(minX, n.x); minY = Math.min(minY, n.y); maxX = Math.max(maxX, n.x); maxY = Math.max(maxY, n.y); });
                const padX = 42;
                const padTop = 32;
                const padBottom = 60; // gives room for node circle, title and rate stats
                boxes.push({
                    name: c.boot_name || c.boot_id || ('boot-' + idx),
                    color: palette[idx % palette.length],
                    local: !!c.local,
                    x: minX - padX, y: minY - padTop,
                    w: (maxX - minX) + padX * 2, h: (maxY - minY) + padTop + padBottom,
                    count: (typeof c.members === 'number') ? c.members : pts.length
                });
            });
            return boxes;
        }

        function renderTopology(ts) {
            topoRAFId = requestAnimationFrame(renderTopology);
            // Skip work when tab is hidden to save CPU.
            if (document.hidden) { topoLastFrameTs = ts; return; }

            const canvas = document.getElementById('topologyCanvas');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            const lightT = document.documentElement.getAttribute('data-theme') === 'light';

            const nodes = window.latestTopoNodes;
            if (!nodes || nodes.length === 0) {
                if (!topoNeedsRedraw) {
                    const idleInt = 1000 / 4;
                    if ((ts - topoLastScheduled) < idleInt) return;
                }
                topoLastScheduled = ts;
                computeTopologyLayout();
                topoLastFrameTs = ts || performance.now();
                topoNeedsRedraw = false;
                return;
            }

            let hasFlow = false;
            for (let i = 0; i < nodes.length; i++) {
                if ((nodes[i].rxSpeed || 0) > TOPO_IDLE_BPS || (nodes[i].txSpeed || 0) > TOPO_IDLE_BPS) { hasFlow = true; break; }
            }
            const idleInterval = 1000 / 4;    // 4 fps gentle pulse when idle
            const activeInterval = 1000 / 60; // full 60 fps when links flow
            if (!topoNeedsRedraw && lightT === topoLastTheme && !hasFlow) {
                if ((ts - topoLastScheduled) < idleInterval) return;
            }
            topoLastScheduled = ts;
            topoLastTheme = lightT;

            const dpr = topoDPR;
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            ctx.clearRect(0, 0, topoCanvasW, topoCanvasH);
            ctx.save();
            ctx.imageSmoothingEnabled = true;
            ctx.translate(topoPanX, topoPanY);
            ctx.scale(topoZoom, topoZoom);

            const centerX = topoCanvasW / 2;
            const centerY = topoCanvasH / 2;

            // --- Links (node -> its parent in the hierarchy) ---
            const nodeByID = topoRebuildIndex(nodes);
            const leafNodes = nodes.reduce((a, nn) => a + (nn.isSelf ? 0 : 1), 0);
            const crowded = leafNodes > 12;

            // --- Boot-cluster hulls (drawn first, behind links & nodes) ---
            const topoClusterBoxes = buildTopoClusterBoxes(nodes, nodeByID);
            topoClusterBoxes.forEach(b => {
                ctx.save();
                ctx.fillStyle = b.color;
                ctx.globalAlpha = b.local ? 0.08 : 0.04;
                ctx.beginPath();
                if (ctx.roundRect) {
                    ctx.roundRect(b.x, b.y, b.w, b.h, 12);
                } else {
                    ctx.rect(b.x, b.y, b.w, b.h);
                }
                ctx.fill();
                ctx.globalAlpha = b.local ? 0.75 : 0.45;
                ctx.strokeStyle = b.color;
                ctx.lineWidth = b.local ? 1.5 : 1.0;
                ctx.setLineDash([6, 4]);
                ctx.stroke();
                ctx.setLineDash([]);

                // Cluster label chip with rounded corners anchored at top-left inside box
                const label = '🟣 ' + b.name + (b.count > 0 ? ` (${b.count})` : '');
                ctx.font = "bold 10px system-ui, -apple-system, sans-serif";
                const lw = topoMeasure(ctx, "bold 10px system-ui, -apple-system, sans-serif", label) + 18;
                ctx.globalAlpha = b.local ? 0.95 : 0.8;
                ctx.fillStyle = b.color;
                ctx.beginPath();
                if (ctx.roundRect) {
                    ctx.roundRect(b.x + 8, b.y + 6, lw, 18, 5);
                } else {
                    ctx.rect(b.x + 8, b.y + 6, lw, 18);
                }
                ctx.fill();
                ctx.fillStyle = "#ffffff";
                ctx.textAlign = 'left';
                ctx.textBaseline = 'middle';
                ctx.fillText(label, b.x + 16, b.y + 15);
                ctx.textBaseline = 'alphabetic';
                ctx.restore();
            });


            for (let i = 0; i < nodes.length; i++) {
                const target = nodes[i];
                if (!target.parentId || !nodeByID[target.parentId]) continue; // self or orphan
                const parent = nodeByID[target.parentId];
                const edgeKey = parent.id + '|' + target.id;
                const edgeHi = topoSelectedId !== null && topoSelectedEdgeSet.has(edgeKey);
                const edgeDim = topoFilterMode !== 'all' && !topoNodeMatchesFilter(target);
                ctx.beginPath();
                ctx.moveTo(parent.x, parent.y);
                ctx.lineTo(target.x, target.y);
                ctx.strokeStyle = edgeHi ? (target.isRelayed ? '#f59e0b' : '#38bdf8') : target.linkColor;
                ctx.lineWidth = edgeHi ? (target.isRelayed ? 2.4 : 3.4) : (target.isRelayed ? 1.8 : 2.8);
                if (target.lineStyle === 'overlay') ctx.setLineDash([10, 5]);
                else if (target.lineStyle === 'circuit') ctx.setLineDash([4, 4]);
                else ctx.setLineDash([]);
                if (edgeHi) { ctx.shadowColor = target.isRelayed ? '#f59e0b' : '#38bdf8'; ctx.shadowBlur = 12; }
                else ctx.shadowBlur = 0;
                ctx.globalAlpha = edgeHi ? 0.95 : (edgeDim ? 0.12 : (topoSelectedId !== null ? 0.18 : 0.55));
                ctx.stroke();
                ctx.shadowBlur = 0;
                ctx.globalAlpha = 1.0;

                const midX = (parent.x + target.x) / 2;
                const midY = (parent.y + target.y) / 2;
                // Pre-existing bug fix: the field actually set on each node by
                // mkNode is seqWinMax (from backend `seq_win_max`), not rxSeqMax.
                // The previous check was silently dead because rxSeqMax was
                // always undefined → 0 → false.
                const seqWinMaxForBlackhole = typeof target.seqWinMax === 'number' ? target.seqWinMax : 0;
                const blackhole = seqWinMaxForBlackhole > 0 &&
                    ((seqWinMaxForBlackhole - target.rxSeq) >= 1024 || (target.dedupDrops > 0 && target.rxSeq < seqWinMaxForBlackhole));

                // ── Mid-link summary pill badge ──
                const isIdle = !(target.txSpeed > 0) && !(target.rxSpeed > 0);
                const rateLine = isIdle
                    ? ''
                    : '↑' + formatRateCompact(target.txSpeed) + '  ↓' + formatRateCompact(target.rxSpeed);

                const relayFirst = (target.isRelayed && target.relayPathNames && target.relayPathNames[0])
                    ? topoShortLabel(target.relayPathNames[0]).slice(0, 12)
                    : '';
                const typeLine = target.isRelayed
                    ? ((t('topo_via') || 'via') + (relayFirst ? ' ' + relayFirst : ''))
                    : (t('topo_summary_direct') || 'direct');
                const dropTxt = target.dedupDrops > 0 ? ` · dup:${target.dedupDrops}` : '';
                const seqWinMax = typeof target.seqWinMax === 'number' ? target.seqWinMax : 0;
                const skew = seqWinMax > 0 ? (seqWinMax - target.rxSeq) : 0;
                const skewTxt = blackhole ? ` · ⚠skew ${skew}` : '';
                let metaLine = `${target.rtt}ms · ${typeLine}${dropTxt}${skewTxt}`;
                if (target.bootHops > 0) metaLine += ' · 🌐boot×' + target.bootHops;

                // Skip when dimmed by active filter/selection
                if (edgeDim || (topoSelectedId !== null && !edgeHi)) continue;

                // Pre-measure widths
                const wRate = rateLine ? topoMeasure(ctx, "bold 9px system-ui, -apple-system, sans-serif", rateLine) : 0;
                const wMeta = topoMeasure(ctx, "8px system-ui, -apple-system, sans-serif", metaLine);
                const contentW = Math.max(wRate, wMeta);

                const padX = 8, padY = 3, lineH = 11;
                const numLines = rateLine ? 2 : 1;
                const boxW = Math.max(54, contentW + padX * 2);
                const boxH = padY * 2 + numLines * lineH;
                const boxX = midX - boxW / 2;
                const boxY = midY - boxH / 2;

                ctx.save();
                ctx.fillStyle = lightT ? "rgba(255,255,255,0.94)" : "rgba(10, 15, 30, 0.88)";
                ctx.strokeStyle = blackhole ? "#f87171" : (edgeHi ? "#38bdf8" : target.linkColor);
                ctx.lineWidth = 1;
                ctx.beginPath();
                if (ctx.roundRect) {
                    ctx.roundRect(boxX, boxY, boxW, boxH, 6);
                } else {
                    ctx.rect(boxX, boxY, boxW, boxH);
                }
                ctx.fill();
                ctx.stroke();

                let yCursor = boxY + padY + 8;
                ctx.textAlign = "center";
                if (rateLine) {
                    ctx.fillStyle = blackhole ? (lightT ? "#dc2626" : "#f87171") : (target.isRelayed ? (lightT ? "#b45309" : "#fcd34d") : (lightT ? "#0284c7" : "#38bdf8"));
                    ctx.font = "bold 9px system-ui, -apple-system, sans-serif";
                    ctx.fillText(rateLine, midX, yCursor);
                    yCursor += lineH;
                }
                ctx.font = "8px system-ui, -apple-system, sans-serif";
                ctx.fillStyle = blackhole ? (lightT ? "#dc2626" : "#fca5a5") : (lightT ? "#475569" : "#94a3b8");
                ctx.fillText(metaLine, midX, yCursor);
                ctx.restore();
            }

            // --- Real-Rate Data-Flow Particles (smooth @60fps) ---
            // Particle speed and density are driven by the REAL per-link byte
            // rate reported by the backend (target.rxSpeed inbound peer->self,
            // target.txSpeed outbound self->peer). Idle links (rate < ~1KB/s)
            // show no flow, so the chart reflects actual traffic truthfully.
            const nowMs = (ts || performance.now());
            const dt = Math.max(0, Math.min(0.1, (nowMs - topoLastFrameTs) / 1000)) || 0.016;
            topoLastFrameTs = nowMs;
            const tsec = nowMs / 1000;
            const selfNode = nodes[0];
            for (let i = 0; i < nodes.length; i++) {
                const target = nodes[i];
                // Particles flow along the actual tree edge (node <-> parent),
                // not always to self. For the root (self) this loop is a no-op
                // here; its traffic to children is drawn when iterating children.
                if (!target.parentId || !nodeByID[target.parentId]) continue;
                const parent = nodeByID[target.parentId];
                if (!topoFlowState[target.id]) topoFlowState[target.id] = { in: Math.random(), out: Math.random() };

                // Map real byte rate -> visual velocity factor (0.08 .. 2.2).
                // Inbound = from the peer toward its parent (up the tree); outbound
                // = toward the peer from its parent (down the tree).
                const inboundRate = target.rxSpeed || 0;   // peer -> parent (RX)
                const outboundRate = target.txSpeed || 0;  // parent -> peer (TX)
                const inVel = inboundRate <= TOPO_IDLE_BPS ? 0 : Math.min(2.2, 0.12 + inboundRate / (256 * 1024));
                const outVel = outboundRate <= TOPO_IDLE_BPS ? 0 : Math.min(2.2, 0.12 + outboundRate / (256 * 1024));

                // Advance each direction's phase by real-rate * dt.
                topoFlowState[target.id].in = (topoFlowState[target.id].in + inVel * dt) % 1.0;
                topoFlowState[target.id].out = (topoFlowState[target.id].out + outVel * dt) % 1.0;

                // Particle density scales with rate: more traffic => more dots.
                const inCount = inVel === 0 ? 0 : Math.min(6, 2 + Math.floor(inboundRate / (64 * 1024)));
                const outCount = outVel === 0 ? 0 : Math.min(6, 2 + Math.floor(outboundRate / (64 * 1024)));

                // Inbound particles travel from peer (target) -> parent (up the tree).
                for (let k = 0; k < inCount; k++) {
                    let p = (topoFlowState[target.id].in + k / inCount) % 1.0;
                    const alpha = 0.35 + 0.65 * Math.sin(Math.PI * p);
                    const px = target.x + (parent.x - target.x) * p;
                    const py = target.y + (parent.y - target.y) * p;
                    ctx.beginPath();
                    ctx.arc(px, py, 4.0, 0, 2 * Math.PI);
                    ctx.fillStyle = target.particleColor;
                    ctx.globalAlpha = alpha;
                    ctx.shadowColor = target.glowColor;
                    ctx.shadowBlur = 10;
                    ctx.fill();
                }
                // Outbound particles travel from parent -> peer (target, down the tree).
                for (let k = 0; k < outCount; k++) {
                    let p = (topoFlowState[target.id].out + k / outCount) % 1.0;
                    const alpha = 0.35 + 0.65 * Math.sin(Math.PI * p);
                    const px = parent.x + (target.x - parent.x) * p;
                    const py = parent.y + (target.y - parent.y) * p;
                    ctx.beginPath();
                    ctx.arc(px, py, 4.0, 0, 2 * Math.PI);
                    ctx.fillStyle = target.particleColor;
                    ctx.globalAlpha = alpha;
                    ctx.shadowColor = target.glowColor;
                    ctx.shadowBlur = 10;
                    ctx.fill();
                }
            }
            ctx.shadowBlur = 0;
            ctx.globalAlpha = 1.0;

            // --- Nodes ---
            // (crowded / leafNodes hoisted above the link-rendering block so
            // edge labels can also drop the peer-name header when dense.)
            for (let i = 0; i < nodes.length; i++) {
                const n = nodes[i];
                const nodeRadius = topoNodeRadius(n, leafNodes);
                const nameSize = nodeRadius >= 14 ? 12 : nodeRadius >= 10 ? 10 : nodeRadius >= 8 ? 9 : 8;
                const nameGap = nodeRadius + (nodeRadius >= 12 ? 14 : nodeRadius + 6);
                const nodeHi = topoSelectedId !== null && topoSelectedPathSet.has(n.id);
                const nodeDim = topoFilterMode !== 'all' && !topoNodeMatchesFilter(n);
                ctx.globalAlpha = nodeDim ? 0.18 : (nodeHi ? 1.0 : (topoSelectedId !== null ? 0.3 : 1.0));

                if (n.isSelf) {
                    const glowRadius = nodeRadius + 3 + Math.sin(tsec * 3) * 2.5;
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, glowRadius, 0, 2 * Math.PI);
                    ctx.fillStyle = "rgba(99, 102, 241, 0.25)";
                    ctx.fill();
                }
                // Radial gradient fill gives each node a subtle lit / 3D look.
                const baseFill = n.isSelf ? "#6366f1" : (n.isBoot ? "#a855f7" : (n.isRelayed ? "#f59e0b" : "#10b981"));
                const strokeCol = n.isSelf ? (lightT ? "#4338ca" : "#a5b4fc") : (n.isBoot ? (lightT ? "#7c3aed" : "#c4b5fd") : (n.isRelayed ? (lightT ? "#b45309" : "#fde68a") : (lightT ? "#047857" : "#6ee7b7")));
                const grad = ctx.createRadialGradient(n.x - nodeRadius * 0.35, n.y - nodeRadius * 0.35, nodeRadius * 0.2, n.x, n.y, nodeRadius);
                grad.addColorStop(0, lightenHex(baseFill, lightT ? 0.35 : 0.45));
                grad.addColorStop(1, baseFill);
                ctx.beginPath();
                ctx.arc(n.x, n.y, nodeRadius, 0, 2 * Math.PI);
                ctx.fillStyle = grad;
                ctx.strokeStyle = nodeHi ? (lightT ? "#0ea5e9" : "#38bdf8") : strokeCol;
                ctx.lineWidth = nodeHi ? (nodeRadius >= 12 ? 4 : 3) : (nodeRadius >= 12 ? 3 : 2);
                if (nodeHi) { ctx.shadowColor = lightT ? "#0ea5e9" : "#38bdf8"; ctx.shadowBlur = 14; }
                else ctx.shadowBlur = 0;
                ctx.fill();
                ctx.stroke();
                ctx.shadowBlur = 0;

                // Boot node: dashed outer ring (pure shape, no glyph).
                if (n.isBoot) {
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, nodeRadius + 4, 0, 2 * Math.PI);
                    ctx.strokeStyle = lightT ? "#7c3aed" : "#c4b5fd";
                    ctx.lineWidth = 1.5;
                    ctx.setLineDash([3, 3]);
                    ctx.stroke();
                    ctx.setLineDash([]);
                }
                // Static peer: small square badge in the top-right quadrant.
                if (n.isStatic) {
                    const bs = Math.max(6, nodeRadius * 0.55);
                    ctx.fillStyle = lightT ? "#1d4ed8" : "#60a5fa";
                    ctx.fillRect(n.x + nodeRadius * 0.7 - bs / 2, n.y - nodeRadius * 0.7 - bs / 2, bs, bs);
                }

                ctx.fillStyle = lightT ? "#0f172a" : "#f8fafc";
                ctx.font = "bold " + nameSize + "px system-ui, -apple-system, sans-serif";
                ctx.textAlign = "center";
                ctx.fillText(topoShortLabel(n.name), n.x, n.y + nameGap);
                if (n.isSelf) {
                    let labelY = n.y + nameGap + nameSize + 4;
                    if (!crowded) {
                        if (n.tapIP) {
                            ctx.fillStyle = "#38bdf8";
                            ctx.font = "10px monospace";
                            ctx.fillText(n.tapIP, n.x, labelY);
                            labelY += 14;
                        }
                        // Role badges: exit-server and/or L2 transit switch.
                        const badges = [];
                        if (n.isExitServer) badges.push('🚪 ' + t('topo_badge_exit_server'));
                        if (n.transitCount > 0) badges.push('🌉 ' + t('topo_badge_transit') + ' ×' + n.transitCount);
                        if (badges.length) {
                            ctx.fillStyle = "#fbbf24";
                            ctx.font = "bold 10px system-ui, -apple-system, sans-serif";
                            ctx.fillText(badges.join('  '), n.x, labelY);
                            labelY += 14;
                        }
                    }
                    // Aggregate throughput through self (transit visibility).
                    if (n.totalTx > 0 || n.totalRx > 0) {
                        ctx.fillStyle = lightT ? "#0369a1" : "#7dd3fc";
                        ctx.font = (crowded ? 8 : 9) + "px system-ui, -apple-system, sans-serif";
                        ctx.fillText('⬆ ' + formatSpeed(n.totalTx) + '  ⬇ ' + formatSpeed(n.totalRx), n.x, labelY);
                    }
                }
 else {
                    // Per-peer live Rx/Tx rate beneath the node name.
                    const peerTx = typeof n.txSpeed === 'number' ? n.txSpeed : 0; // self -> peer
                    const peerRx = typeof n.rxSpeed === 'number' ? n.rxSpeed : 0; // peer -> self
                    ctx.fillStyle = lightT ? "#475569" : "#94a3b8";
                    ctx.font = (nodeRadius >= 10 ? 9 : 8) + "px system-ui, -apple-system, sans-serif";
                    ctx.fillText("⬆ " + formatSpeed(peerTx) + "  ⬇ " + formatSpeed(peerRx), n.x, n.y + nameGap + nameSize + 3);
                    // Exit-server peer marker (small, above the node name).
                    if (n.peer && n.peer.is_exit_node) {
                        ctx.fillStyle = lightT ? "#6d28d9" : "#c4b5fd";
                        ctx.font = (nodeRadius >= 10 ? 10 : 8) + "px system-ui, -apple-system, sans-serif";
                        ctx.fillText('🚪', n.x, n.y - nodeRadius - 5);
                    }
                }
            }
            ctx.globalAlpha = 1.0;

            if (nodes.length === 1) {
                ctx.fillStyle = "rgba(148, 163, 184, 0.75)";
                ctx.font = "italic 12px system-ui, -apple-system, sans-serif";
                ctx.textAlign = "center";
                ctx.fillText(t('topo_standalone'), centerX, centerY + 55);
            }

            ctx.restore();
            topoNeedsRedraw = false; // drew this frame; idle throttle can now gate us
        }

        // Kick off the 60fps render loop once.
        function startTopologyLoop() {
            if (topoRAFId === null) topoRAFId = requestAnimationFrame(renderTopology);
        }

        function openAddStaticPeerModal() {
            const m = document.getElementById('addStaticPeerModal');
            if (m) { m.classList.add('active'); m.style.display = 'flex'; }
        }

        function closeAddStaticPeerModal() {
            const m = document.getElementById('addStaticPeerModal');
            if (m) { m.classList.remove('active'); m.style.display = 'none'; }
        }

        async function submitAddStaticPeer() {
            const input = document.getElementById('addStaticMultiaddrInput');
            if (!input || !input.value.trim()) {
                showToast('❌ ' + (t('err_enter_multiaddr') || 'Please enter a valid Multiaddr string'), true);
                return;
            }
            const ma = input.value.trim();
            showToast(`🚀 ${t('toast_testing_adding') || 'Testing and adding static peer'}: ${ma}...`, false);
            try {
                const res = await fetch('/api/peer/add_static', withAuth({
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ multiaddr: ma })
                }));
                const json = await res.json();
                if (json && json.success) {
                    showToast('⚡ ' + (t('toast_static_added') || 'Static peer added and permanently registered in Peerstore!'), false);
                    closeAddStaticPeerModal();
                    input.value = '';
                    fetchStats();
                } else {
                    showToast(`❌ ${t('toast_add_failed') || 'Add static peer failed'}: ${json.error || 'Unknown error'}`, true);
                }
            } catch(e) {
                showToast(`❌ ${t('toast_req_err') || 'Request error'}: ${e.message}`, true);
            }
        }

        async function openPeerDiagnosticsModal(peerID) {
            const m = document.getElementById('peerDiagnosticsModal');
            if (!m) return;
            m.classList.add('active');
            m.style.display = 'flex';

            const title = document.getElementById('diagModalTitle');
            const content = document.getElementById('diagModalContent');
            title.innerText = `⚡ Diagnostics for ${peerID.substring(0, 16)}...`;
            content.innerHTML = `<div style="text-align:center; padding:30px;"><div style="color:var(--accent-cyan); font-weight:bold; font-size:1.1rem; margin-bottom:8px;">${t('probing_pathways_title')}</div><div style="color:var(--text-secondary); font-size:0.85rem;">${t('probing_pathways_desc')}</div></div>`;

            try {
                const res = await fetch('/api/multiaddr-test', withAuth({
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ peer_id: peerID })
                }));
                const results = await res.json();
                if (Array.isArray(results) && results.length > 0) {
                    let html = `<div style="margin-bottom:12px; font-weight:600; color:var(--accent-cyan);">Discovered Multiaddr Pathways (${results.length}):</div>`;
                    html += `<div style="display:flex; flex-direction:column; gap:8px;">`;
                    results.forEach(r => {
                        const statusColor = r.reachable ? '#34d399' : '#f87171';
                        const isRelay = r.addr.includes('/p2p-circuit');
                        const tag = isRelay ? '🔀 Circuit Relay' : (r.is_active ? '🟢 Active Path' : '⚡ Candidate');
                        html += `
                            <div style="background:var(--surface-fill); padding:10px 14px; border-radius:8px; border:1px solid var(--glass-fill-strong); display:flex; justify-content:space-between; align-items:center;">
                                <div style="font-family:monospace; font-size:0.82rem; word-break:break-all; flex:1; margin-right:12px;">
                                    <span style="color:${statusColor}; font-weight:bold;">[${tag}]</span> ${escapeHTML(r.addr)}
                                </div>
                                <div style="display:flex; align-items:center; gap:10px;">
                                    <span style="font-weight:bold; color:${r.reachable ? 'var(--success)' : 'var(--text-secondary)'};">${r.reachable ? r.rtt_ms + ' ms' : 'Unreachable'}</span>
                                    <button class="btn-glass" style="padding:2px 8px; font-size:0.75rem;" data-onclick="testSingleMultiaddrEcho(${attrStr(peerID)}, ${attrStr(r.addr)})">${t('test_echo')}</button>
                                </div>
                            </div>
                        `;
                    });
                    html += `</div>`;
                    content.innerHTML = html;
                } else {
                    content.innerHTML = `<div style="color:var(--danger); text-align:center; padding:20px;">No multiaddr candidate paths returned for peer.</div>`;
                }
            } catch(e) {
                content.innerHTML = `<div style="color:var(--danger); text-align:center; padding:20px;">Diagnostics request failed: ${e.message}</div>`;
            }
        }

        function closePeerDiagnosticsModal() {
            const m = document.getElementById('peerDiagnosticsModal');
            if (m) { m.classList.remove('active'); m.style.display = 'none'; }
        }

        // ---- Packet Capture (pcap) WebUI logic ----
        //
        // Live frame delivery now rides on a WebSocket (/api/pcap/stream).
        // The HTTP /api/pcap/packets route is kept as a polling fallback when
        // the WebSocket repeatedly fails to connect (corporate proxies, locked
        // down browsers, etc.). The two paths share pcap.lastSeq so a late-
        // arriving fallback request can resume without re-shipping frames the
        // WebSocket already delivered.
        const pcap = {
            running: false,
            lastSeq: 0,
            total: 0,
            paused: false,
        };

        const pcapState = {
            running: false,
            count: 0,
        };

        function applyPcapStateToBadge(state) {
            if (!state) return;
            pcapState.running = !!state.running;
            pcapState.count = state.count || 0;
            pcap.running = pcapState.running;
            pcap.total = pcapState.count;
            const badge = document.getElementById('pcapStateBadge');
            const btn = document.getElementById('pcapToggleBtn');
            if (!badge || !btn) return;
            if (state.running) {
                badge.textContent = t('pcap_running') + ' (' + state.count + ')';
                badge.classList.add('running');
                badge.classList.remove('stopped');
                badge.style.background = '';
                badge.style.color = '';
                btn.innerHTML = '<svg class="ico btn-ico" aria-hidden="true"><use href="#ic-pause"/></svg><span>' + t('pcap_pause') + '</span>';
            } else {
                badge.textContent = t('pcap_stopped') + ' (' + state.count + ')';
                badge.classList.add('stopped');
                badge.classList.remove('running');
                badge.style.background = '';
                badge.style.color = '';
                btn.innerHTML = '<svg class="ico btn-ico" aria-hidden="true"><use href="#ic-play"/></svg><span>' + t('pcap_start') + '</span>';
            }
        }

        async function pcapRefreshState() {
            // Belt-and-suspenders: the WebSocket pushes state on connect and
            // on every transition. We still poll /api/pcap/state every 1.5s so
            // the badge stays in sync even when the WebSocket briefly
            // disconnects, but the response is tiny (~80 bytes).
            try {
                const res = await fetch('/api/pcap/state', withAuth());
                if (!res.ok) return;
                applyPcapStateToBadge(await res.json());
            } catch (e) { /* ignore */ }
        }

        // ---- pcapStream: WebSocket client for /api/pcap/stream ----
        //
        // State machine:
        //   off        — never started or explicitly stopped
        //   connecting — handshake in flight
        //   live       — server is pushing frames; backlog received
        //   polling    — WebSocket repeatedly failed; HTTP fallback active
        //
        // `pcapStream.connect()` is idempotent: calling it on an already-open
        // connection is a no-op. Auto-reconnect uses exponential back-off
        // capped at 30s; after six failed attempts we give up and fall back
        // to the legacy /api/pcap/packets poller.
        const pcapStream = {
            ws: null,
            connecting: false,
            status: 'off',        // off | connecting | live | polling
            retry: 0,
            dropped: 0,
            retryTimer: null,
            pollTimer: null,
            useFallback: false,

            connect() {
                if (this.ws || this.connecting) return;
                if (typeof WebSocket === 'undefined') {
                    // Old browsers: straight to polling fallback.
                    this.useFallback = true;
                    this.status = 'polling';
                    this._updateUI();
                    this._startPolling();
                    return;
                }
                const tok = (typeof getAuthToken === 'function' && getAuthToken()) || '';
                const proto = (location.protocol === 'https:') ? 'wss:' : 'ws:';
                let url = proto + '//' + location.host + '/api/pcap/stream?backlog=200';
                // On reconnect, only ask for frames the table doesn't already have.
                if (pcap && pcap.lastSeq) url += '&since=' + pcap.lastSeq;
                if (tok) url += '&token=' + encodeURIComponent(tok);
                this.connecting = true;
                this.status = 'connecting';
                this._updateUI();
                let ws;
                try { ws = new WebSocket(url); }
                catch (e) { this._onFail(); return; }
                this.ws = ws;

                ws.onopen = () => {
                    this.connecting = false;
                    this.status = 'live';
                    this.retry = 0;
                    this.useFallback = false;
                    if (this.pollTimer) { clearInterval(this.pollTimer); this.pollTimer = null; }
                    this._updateUI();
                };
                ws.onmessage = (msg) => {
                    try {
                        const env = JSON.parse(msg.data);
                        this._handle(env);
                    } catch (e) { /* ignore parse errors */ }
                };
                ws.onerror = () => { /* onclose will follow */ };
                ws.onclose = () => {
                    this.ws = null;
                    this.connecting = false;
                    if (this.status === 'off') return; // explicit disconnect
                    this._scheduleRetry();
                };
            },

            disconnect() {
                this.status = 'off';
                if (this.retryTimer) { clearTimeout(this.retryTimer); this.retryTimer = null; }
                if (this.pollTimer)   { clearInterval(this.pollTimer); this.pollTimer = null; }
                if (this.ws) { try { this.ws.close(); } catch (e) {} this.ws = null; }
                this._updateUI();
            },

            _scheduleRetry() {
                if (this.retry >= 6) {
                    // Give up on the WebSocket; fall back to JSON polling.
                    this.useFallback = true;
                    this.status = 'polling';
                    this._updateUI();
                    this._startPolling();
                    return;
                }
                this.retry++;
                const delay = Math.min(1000 * Math.pow(2, this.retry), 30000);
                this.status = 'connecting';
                this._updateUI();
                this.retryTimer = setTimeout(() => {
                    this.retryTimer = null;
                    this.connect();
                }, delay);
            },

            _startPolling() {
                if (this.pollTimer) return;
                // pcapPoll is the legacy incrementing fetcher.
                this.pollTimer = setInterval(pcapPoll, 1000);
            },

            _onFail() {
                this.connecting = false;
                this._scheduleRetry();
            },

            _handle(env) {
                if (!env || !env.type) return;
                const noteDropped = () => {
                    if (env.dropped) {
                        this.dropped = env.dropped;
                        this._updateUI();
                    }
                };
                switch (env.type) {
                    case 'state':
                        applyPcapStateToBadge(env.state);
                        noteDropped();
                        break;
                    case 'backlog':
                    case 'frame':
                    case 'frames':
                        pcapBuffer(env);
                        noteDropped();
                        break;
                    case 'cleared':
                        pcapClearTable();
                        break;
                    case 'error':
                        try { console.warn('pcap stream:', env.error); } catch (e) {}
                        break;
                    case 'pong':
                        break;
                    default:
                        break;
                }
            },

            _updateUI() {
                const ind = document.getElementById('pcapStreamIndicator');
                if (!ind) return;
                ind.classList.remove('stream-off', 'stream-connecting', 'stream-live', 'stream-polling');
                if (this.status === 'off')        ind.classList.add('stream-off');
                else if (this.status === 'connecting') ind.classList.add('stream-connecting');
                else if (this.status === 'live')      ind.classList.add('stream-live');
                else if (this.status === 'polling')   ind.classList.add('stream-polling');
                const labelKey = this.status === 'live' ? 'pcap_stream_live'
                                : this.status === 'connecting' ? 'pcap_stream_connecting'
                                : this.status === 'polling' ? 'pcap_stream_polling' : 'pcap_stream_off';
                const baseTitle = (typeof t === 'function') ? t(labelKey) : labelKey;
                const dropNote = this.dropped ? ' · ' + this.dropped + ' ' + ((typeof t === 'function') ? t('pcap_stream_dropped') : 'dropped') : '';
                ind.title = baseTitle + dropNote;
            },
        };

        // ---- logStream: WebSocket client for /api/logs/stream ----
        //
        // State machine (mirrors pcapStream):
        //   off        — never started or explicitly stopped
        //   connecting — handshake in flight
        //   live       — server is pushing new log lines; backlog received
        //   polling    — WebSocket repeatedly failed; HTTP fallback active
        //
        // `logStream.connect()` is idempotent. Auto-reconnect uses exponential
        // back-off capped at 30s; after six failed attempts we fall back to the
        // legacy /api/logs poller (fetchLogs). Only NEW lines are transmitted —
        // the server keeps the ring buffer and the client asks for a one-time
        // backlog on connect, then receives incremental entries from there on.
        const logStream = {
            ws: null,
            connecting: false,
            status: 'off',        // off | connecting | live | polling
            retry: 0,
            dropped: 0,
            retryTimer: null,
            pollTimer: null,
            useFallback: false,

            connect() {
                if (this.ws || this.connecting) return;
                if (typeof WebSocket === 'undefined') {
                    // Old browsers: straight to polling fallback.
                    this.useFallback = true;
                    this.status = 'polling';
                    this._updateUI();
                    this._startPolling();
                    return;
                }
                const tok = (typeof getAuthToken === 'function' && getAuthToken()) || '';
                const proto = (location.protocol === 'https:') ? 'wss:' : 'ws:';
                let url = proto + '//' + location.host + '/api/logs/stream?backlog=100';
                if (tok) url += '&token=' + encodeURIComponent(tok);
                this.connecting = true;
                this.status = 'connecting';
                this._updateUI();
                let ws;
                try { ws = new WebSocket(url); }
                catch (e) { this._onFail(); return; }
                this.ws = ws;

                ws.onopen = () => {
                    this.connecting = false;
                    this.status = 'live';
                    this.retry = 0;
                    this.useFallback = false;
                    if (this.pollTimer) { clearInterval(this.pollTimer); this.pollTimer = null; }
                    this._updateUI();
                };
                ws.onmessage = (msg) => {
                    try {
                        const env = JSON.parse(msg.data);
                        this._handle(env);
                    } catch (e) { /* ignore parse errors */ }
                };
                ws.onerror = () => { /* onclose will follow */ };
                ws.onclose = () => {
                    this.ws = null;
                    this.connecting = false;
                    if (this.status === 'off') return; // explicit disconnect
                    this._scheduleRetry();
                };
            },

            disconnect() {
                this.status = 'off';
                if (this.retryTimer) { clearTimeout(this.retryTimer); this.retryTimer = null; }
                if (this.pollTimer)   { clearInterval(this.pollTimer); this.pollTimer = null; }
                if (this.ws) { try { this.ws.close(); } catch (e) {} this.ws = null; }
                this._updateUI();
            },

            _scheduleRetry() {
                if (this.retry >= 6) {
                    // Give up on the WebSocket; fall back to JSON polling.
                    this.useFallback = true;
                    this.status = 'polling';
                    this._updateUI();
                    this._startPolling();
                    return;
                }
                this.retry++;
                const delay = Math.min(1000 * Math.pow(2, this.retry), 30000);
                this.status = 'connecting';
                this._updateUI();
                this.retryTimer = setTimeout(() => {
                    this.retryTimer = null;
                    this.connect();
                }, delay);
            },

            _startPolling() {
                if (this.pollTimer) return;
                // Legacy one-shot JSON poller. It refetches the full recent log
                // set each tick, but only while the WebSocket is unavailable.
                this.pollTimer = setInterval(fetchLogs, 2500);
            },

            _onFail() {
                this.connecting = false;
                this._scheduleRetry();
            },

            _handle(env) {
                if (!env || !env.type) return;
                switch (env.type) {
                    case 'backlog':
                        if (Array.isArray(env.entries)) renderLogBacklog(env.entries);
                        if (env.dropped) { this.dropped = env.dropped; this._updateUI(); }
                        break;
                    case 'entry':
                        // Respect pause: when paused we don't render, but the
                        // server keeps the ring; unpausing triggers a full
                        // fetchLogs() resync so nothing is lost.
                        if (!logsPaused && env.entry) appendLogEntry(env.entry);
                        if (env.dropped) { this.dropped = env.dropped; this._updateUI(); }
                        break;
                    case 'cleared':
                        clearLogView();
                        break;
                    case 'stats':
                        if (env.dropped) { this.dropped = env.dropped; this._updateUI(); }
                        break;
                    case 'error':
                        try { console.warn('log stream:', env.error); } catch (e) {}
                        break;
                    default:
                        break;
                }
            },

            _updateUI() {
                const ind = document.getElementById('logStreamIndicator');
                if (!ind) return;
                ind.classList.remove('stream-off', 'stream-connecting', 'stream-live', 'stream-polling');
                if (this.status === 'off')        ind.classList.add('stream-off');
                else if (this.status === 'connecting') ind.classList.add('stream-connecting');
                else if (this.status === 'live')      ind.classList.add('stream-live');
                else if (this.status === 'polling')   ind.classList.add('stream-polling');
                const labelKey = this.status === 'live' ? 'log_stream_live'
                                : this.status === 'connecting' ? 'log_stream_connecting'
                                : this.status === 'polling' ? 'log_stream_polling' : 'log_stream_off';
                const baseTitle = (typeof t === 'function') ? t(labelKey) : labelKey;
                const dropNote = this.dropped ? ' · ' + this.dropped + ' ' + ((typeof t === 'function') ? t('log_stream_dropped') : 'dropped') : '';
                ind.title = baseTitle + dropNote;
            },
        };

        // ---- row builder & ingestion (shared between WS and HTTP fallback) ----
        function pcapBuildRow(f, isRepeat) {
            const tr = document.createElement('tr');
            tr.title = t('pcap_click_hint');
            tr.onclick = function () { openPcapModal(f); };
            const dirCls = f.dir === 'tx' ? 'dir-tx' : 'dir-rx';
            const time = pcapFmtTime(f.ts);
            const cells = [
                f.seq != null ? f.seq : '-',
                time,
                f.dir || '-',
                f.src_mac || '-',
                f.dst_mac || '-',
                f.ether_type || '-',
                f.protocol || '-',
                f.src_ip || '-',
                f.dst_ip || '-',
                (f.src_port && f.src_port > 0) ? (f.src_port + '→' + f.dst_port) : '-',
                f.tcp_flags || '-',
                f.dns_q || '-',
                f.sni || '-',
                f.from_peer || '-',
                f.to_peer || '-',
                f.len != null ? f.len : '-',
                f.info || '-',
                (f.hex && f.hex.length > 48) ? (f.hex.slice(0, 48) + '…') : (f.hex || '-')
            ];
            // classNames aligned 1:1 with the `cells` array above.
            const cellClasses = [
                null, null, dirCls, null, null, null, null, null, null, null,
                null, 'pcap-dns', 'pcap-sni', null, null, null, 'pcap-info', 'pcap-hex'
            ];
            for (let i = 0; i < cells.length; i++) {
                const td = document.createElement('td');
                if (cellClasses[i]) td.className = cellClasses[i];
                td.textContent = cells[i];
                tr.appendChild(td);
            }
            // Tag consecutive identical frames so an operator scanning the
            // list understands it's a legitimate multi-cast / mDNS re-emit,
            // not a render duplication. The mark is rendered in BOTH the
            // seq cell (the ↻ icon) and on hover via a tooltip covering the
            // whole row, so a glance or a mousedown both tell the story.
            if (isRepeat) {
                tr.classList.add('pcap-row-dupe');
                tr.title = (typeof t === 'function')
                    ? t('pcap_dup_repeat_row')
                    : 'Repeated frame — same hex/payload as the previous row. Common with mDNS / multicast re-emits.';
                const tag = document.createElement('span');
                tag.className = 'pcap-dup-tag';
                tag.textContent = '';
                tag.setAttribute('aria-label', 'repeat');
                tag.title = (typeof t === 'function') ? t('pcap_dup_repeat') : 'repeated frame (mDNS / multicast retransmit)';
                const seqTd = tr.firstChild;
                if (seqTd) seqTd.appendChild(tag);
            }
            return tr;
        }

        // ---- coalesced ingestion ------------------------------------------
        // The WebSocket can deliver dozens of `frames` messages per second.
        // Writing to the DOM synchronously on every message thrashes the main
        // thread (each insert reflows the whole table). We buffer incoming
        // frames and flush to the DOM at most once per animation frame, which
        // caps layout work at ~60 Hz regardless of capture rate. When the tab
        // is backgrounded we still advance the dedup cursor (so a later
        // reconnect doesn't refetch the gap) but skip all DOM work entirely.
        const PCAP_MAX_ROWS = 500;
        let pcapIngestBuffer = [];
        let pcapIngestScheduled = false;

        function pcapBuffer(env) {
            const frames = (env.type === 'frame') ? [env.frame] : (env.frames || []);
            if (frames.length === 0) return;
            if (typeof document !== 'undefined' && document.hidden) {
                // Backgrounded: keep the dedup cursor current so we don't
                // refetch the gap on return, but build zero rows.
                for (const f of frames) {
                    if (f.seq != null && f.seq > pcap.lastSeq) pcap.lastSeq = f.seq;
                }
                return;
            }
            for (const f of frames) pcapIngestBuffer.push(f);
            if (!pcapIngestScheduled) {
                pcapIngestScheduled = true;
                requestAnimationFrame(pcapIngestFlush);
            }
        }

        function pcapIngestFlush() {
            pcapIngestScheduled = false;
            if (pcapIngestBuffer.length === 0) return;
            const frames = pcapIngestBuffer;
            pcapIngestBuffer = [];
            pcapIngestFrames(frames);
        }

        // Allocation-light time formatter — adds .ms so back-to-back frames
        // (typical of mDNS / multicast re-emits) aren't flattened into the
        // same HH:MM:SS cell, which makes the operator think the table is
        // duplicating rows.
        function pcapFmtTime(ts) {
            const d = new Date(ts);
            const p2 = (n) => (n < 10 ? '0' : '') + n;
            const p3 = (n) => (n < 10 ? '00' : (n < 100 ? '0' : '')) + n;
            return p2(d.getHours()) + ':' + p2(d.getMinutes()) + ':' + p2(d.getSeconds()) + '.' + p3(d.getMilliseconds());
        }

        // A "signature" is the tuple of fields that uniquely identify an
        // otherwise-identical frame (mDNS queries, ARP probes, etc. are
        // re-broadcast as identical bytes within milliseconds). Comparing
        // direction + MACs + IPs + L4 ports + protocol lets us tag the
        // second-and-later occurrences as repeat captures without false
        // positives on rapid legitimate flows (those change by seq/port).
        function pcapSig(f) {
            return [
                f.dir || '',
                f.src_mac || '',
                f.dst_mac || '',
                f.src_ip || '',
                f.dst_ip || '',
                f.protocol || '',
                f.src_port || 0,
                f.dst_port || 0,
                f.tcp_flags || ''
            ].join('|');
        }

        // pcapIngestFrames writes an array of CapturedFrame objects into the
        // DOM. It is only ever called from pcapIngestFlush (rAF) or the legacy
        // HTTP poller, never directly from the message handler. Dedup by Seq
        // prevents double-render from backlog/live overlap; the table is capped
        // so memory and layout cost stay bounded for hours of capture. We also
        // tag back-to-back identical frames (same MACs/IPs/ports/proto) as
        // "repeat" so the operator can tell at a glance whether a streak of
        // rows is a legitimate mDNS / ARP / multicast re-emit.
        function pcapIngestFrames(frames) {
            if (!frames || frames.length === 0) return;
            const body = document.getElementById('pcapBody');
            if (!body) return;
            const empty = document.getElementById('pcapEmpty');
            if (empty) empty.style.display = 'none';
            let appended = 0;
            const frag = document.createDocumentFragment();
            for (const f of frames) {
                if (f.seq == null) continue;
                if (f.seq <= pcap.lastSeq) continue;
                pcap.lastSeq = f.seq;
                const sig = pcapSig(f);
                const isRepeat = (sig === pcap.lastSig);
                pcap.lastSig = sig;
                frag.appendChild(pcapBuildRow(f, isRepeat));
                appended++;
            }
            if (appended === 0) return;
            body.appendChild(frag);
            // Bound the table: drop oldest rows once over the cap. A smaller
            // cap (vs. the server's multi-thousand buffer) keeps table-layout
            // cheap — we only keep enough history to be useful on screen.
            if (body.childElementCount > PCAP_MAX_ROWS) {
                let over = body.childElementCount - PCAP_MAX_ROWS;
                while (over-- > 0 && body.firstChild) body.removeChild(body.firstChild);
                // After trimming the head, the new first row is no longer
                // adjacent to its predecessor in our tracking; reset so the
                // next append isn't mis-tagged as a repeat of a row we just
                // dropped.
                pcap.lastSig = '';
            }
            // Autoscroll: only if the operator opted in, and once per frame
            // (reading scrollHeight forces a layout, so avoid doing it more
            // often than necessary).
            const auto = document.getElementById('pcapAutoScroll');
            if (auto && auto.checked) {
                const wrap = document.getElementById('pcapScroll');
                if (wrap) wrap.scrollTop = wrap.scrollHeight;
            }
        }

        function pcapClearTable() {
            pcap.lastSeq = 0;
            pcap.lastSig = '';
            const body = document.getElementById('pcapBody');
            if (body) body.innerHTML = '';
            const empty = document.getElementById('pcapEmpty');
            if (empty) empty.style.display = '';
        }

        let isPollingPcap = false;
        async function pcapPoll() {
            // HTTP fallback: only used when the WebSocket cannot be
            // established. Identical dedup + DOM cap as the WS path.
            if (isPollingPcap || !pcap.running) return;
            if (document.hidden) return;
            isPollingPcap = true;
            try {
                const res = await fetchWithTimeout('/api/pcap/packets?since=' + pcap.lastSeq + '&limit=500', {}, 3000);
                if (!res.ok) return;
                const data = await res.json();
                pcapIngestFrames(data.frames || []);
            } catch (e) { /* ignore */ } finally {
                isPollingPcap = false;
            }
        }

        async function pcapToggle() {
            const action = pcap.running ? 'stop' : 'start';
            await fetch('/api/pcap/' + action, withAuth({ method: 'POST' }));
            await pcapRefreshState();
            // The WebSocket will receive a state event and refresh the badge;
            // for the HTTP-fallback path we still want to drain any frames
            // immediately so the user sees the first arrivals.
            if (!pcap.running && pcapStream.useFallback) pcapPoll();
        }

        async function pcapClear() {
            await fetch('/api/pcap/clear', withAuth({ method: 'POST' }));
            // The WebSocket will deliver a `cleared` event; locally we wipe
            // immediately so the UI feels responsive even if the server-side
            // broadcast is delayed by a slow event loop.
            pcapClearTable();
            await pcapRefreshState();
        }

        // Format a raw base64 frame into a readable hex+ASCII dump.
        function pcapHexDump(b64) {
            try {
                const bin = atob(b64);
                const bytes = new Uint8Array(bin.length);
                for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
                const lines = [];
                const row = 16;
                for (let off = 0; off < bytes.length; off += row) {
                    let hex = '', asc = '';
                    for (let j = 0; j < row; j++) {
                        if (off + j < bytes.length) {
                            const b = bytes[off + j];
                            hex += ('0' + b.toString(16)).slice(-2) + ' ';
                            if (j === 7) hex += ' ';
                            asc += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
                        } else {
                            hex += '   ';
                            asc += ' ';
                        }
                    }
                    lines.push(('00000' + off.toString(16)).slice(-6) + '  ' + hex + ' ' + asc);
                }
                return lines.join('\n');
            } catch (e) {
                return '(无法解析原始帧)';
            }
        }

        function openPcapModal(f) {
            const time = new Date(f.ts).toLocaleString(currentLang || 'zh-CN', { hour12: false });
            const dirTxt = f.dir === 'tx' ? t('pcap_dir_tx') : t('pcap_dir_rx');
            // Flat summary (always useful at a glance)
            const meta = [
                [t('pcap_f_seq'), f.seq],
                [t('pcap_f_time'), time],
                [t('pcap_f_dir'), dirTxt],
                [t('pcap_f_len'), f.len + ' bytes'],
                [t('pcap_f_frompeer'), f.from_peer || '-'],
                [t('pcap_f_topeer'), f.to_peer || '-'],
                [t('pcap_f_info'), f.info || '-']
            ];
            let metaHtml = '<table class="pkt-meta-table">';
            for (const [k, v] of meta) {
                metaHtml += '<tr>' +
                    '<td class="pkt-meta-key">' + k + '</td>' +
                    '<td class="pkt-meta-val">' + (v === '' || v === 0 || v === '-' ? '-' : v) + '</td>' +
                    '</tr>';
            }
            metaHtml += '</table>';

            // Wireshark-style layered protocol dissection tree
            const tree = buildProtocolTree(f);

            document.getElementById('pcapModalBody').innerHTML = metaHtml + tree;
            document.getElementById('pcapModalHex').value = pcapHexDump(f.raw || '');
            document.getElementById('pcapModal').classList.add('active');
        }

        // buildProtocolTree renders a hierarchical, byte-offset-aware dissection
        // of a captured frame (Ethernet → VLAN → L3 → L4 → App), mirroring the
        // collapsible tree view of protocol analyzers. Offsets are shown as
        // "start-end" byte ranges (inclusive) so they line up with the hex dump.
        function buildProtocolTree(f) {
            const hasVlan = (f.vlan_id && f.vlan_id > 0);
            const l2 = hasVlan ? 18 : 14; // Ethernet header length (VLAN adds 4)
            const layers = [];

            // Layer 0: Frame
            layers.push({
                name: t('pcap_layer_frame'),
                color: '#38bdf8',
                summary: (f.len || 0) + ' bytes · ' + (f.dir === 'tx' ? t('pcap_dir_tx') : t('pcap_dir_rx')),
                off: '0-' + ((f.len || 0) - 1),
                rows: [
                    [t('pcap_f_len'), (f.len || 0) + ' bytes', '0-' + ((f.len || 0) - 1)],
                    [t('pcap_f_dir'), f.dir === 'tx' ? t('pcap_dir_tx') : t('pcap_dir_rx'), '-']
                ]
            });

            // Layer 1: Ethernet II
            const ethRows = [
                [t('pcap_f_dstmac'), f.dst_mac || '-', '0-5'],
                [t('pcap_f_srcmac'), f.src_mac || '-', '6-11']
            ];
            let ethOff = '0-13';
            if (hasVlan) {
                ethRows.push([t('pcap_f_etype'), '0x8100 (VLAN)', '12-13']);
                ethOff = '0-17';
            } else {
                ethRows.push([t('pcap_f_etype'), f.ether_type || '-', '12-13']);
            }
            layers.push({
                name: 'Ethernet II',
                color: '#a78bfa',
                summary: (f.src_mac || '?') + ' → ' + (f.dst_mac || '?'),
                off: ethOff,
                rows: ethRows
            });

            // Layer 1b: 802.1Q VLAN
            if (hasVlan) {
                layers.push({
                    name: '802.1Q Virtual LAN',
                    color: '#c084fc',
                    summary: 'VID ' + f.vlan_id + ' · PRI -',
                    off: '14-17',
                    rows: [
                        [t('pcap_f_vlan'), f.vlan_id, '14-15'],
                        [t('pcap_f_etype'), f.ether_type || '-', '16-17']
                    ]
                });
            }

            // Layer 2: L3
            const et = (f.ether_type || '').toLowerCase();
            if (et === '0x0800' || f.protocol === 'IPv4') {
                const rows = [
                    [t('pcap_f_srcip'), f.src_ip || '-', l2 + '-' + (l2 + 3)],
                    [t('pcap_f_dstip'), f.dst_ip || '-', (l2 + 4) + '-' + (l2 + 7)],
                    [t('pcap_f_ttl'), (f.ttl && f.ttl > 0) ? f.ttl : '-', (l2 + 8) + '-' + (l2 + 8)]
                ];
                if (f.l4_proto) rows.push([t('pcap_f_l4proto'), f.l4_proto, (l2 + 9) + '-' + (l2 + 9)]);
                layers.push({ name: 'Internet Protocol Version 4', color: '#34d399', summary: (f.src_ip || '?') + ' → ' + (f.dst_ip || '?'), off: l2 + '-' + (l2 + 19), rows: rows });
            } else if (et === '0x86dd' || f.protocol === 'IPv6') {
                const rows = [
                    [t('pcap_f_srcip'), f.src_ip || '-', l2 + '-' + (l2 + 15)],
                    [t('pcap_f_dstip'), f.dst_ip || '-', (l2 + 16) + '-' + (l2 + 31)],
                    [t('pcap_f_ttl'), (f.ttl && f.ttl > 0) ? f.ttl : '-', (l2 + 7) + '-' + (l2 + 7)]
                ];
                if (f.l4_proto) rows.push([t('pcap_f_l4proto'), f.l4_proto, (l2 + 6) + '-' + (l2 + 6)]);
                layers.push({ name: 'Internet Protocol Version 6', color: '#34d399', summary: (f.src_ip || '?') + ' → ' + (f.dst_ip || '?'), off: l2 + '-' + (l2 + 39), rows: rows });
            } else if (et === '0x0806' || f.protocol === 'ARP') {
                const rows = [
                    [t('pcap_f_arpop'), f.arp_op || '-', (l2) + '-' + (l2 + 1)],
                    [t('pcap_f_arpsmac'), f.arp_smac || '-', (l2 + 8) + '-' + (l2 + 13)],
                    [t('pcap_f_srcip'), f.src_ip || '-', (l2 + 14) + '-' + (l2 + 17)],
                    [t('pcap_f_arpdmac'), f.arp_dmac || '-', (l2 + 18) + '-' + (l2 + 23)],
                    [t('pcap_f_dstip'), f.dst_ip || '-', (l2 + 24) + '-' + (l2 + 27)]
                ];
                layers.push({ name: 'Address Resolution Protocol', color: '#fbbf24', summary: (f.arp_op || 'ARP'), off: l2 + '-' + (l2 + 27), rows: rows });
            } else if (f.protocol === 'NDP' || f.arp_op) {
                layers.push({ name: 'Neighbor Discovery Protocol', color: '#fbbf24', summary: f.info || 'ICMPv6', off: l2 + '-', rows: [
                    [t('pcap_f_srcip'), f.src_ip || '-', '-'],
                    [t('pcap_f_dstip'), f.dst_ip || '-', '-']
                ] });
            }

            // Layer 3: L4
            if (f.l4_proto === 'TCP' || f.l4_proto === 'UDP' || f.l4_proto === 'ICMP') {
                const rows = [];
                if (f.src_port) rows.push([t('pcap_f_srcport'), f.src_port, '-']);
                if (f.dst_port) rows.push([t('pcap_f_dstport'), f.dst_port, '-']);
                if (f.l4_proto === 'TCP') {
                    if (f.tcp_flags) rows.push([t('pcap_f_tcpflags'), f.tcp_flags, '-']);
                    if (f.tcp_seq) rows.push([t('pcap_f_tcpseq'), f.tcp_seq, '-']);
                    if (f.tcp_win) rows.push([t('pcap_f_tcpwin'), f.tcp_win, '-']);
                }
                layers.push({ name: f.l4_proto + ' (' + ({ TCP: 'Transmission Control', UDP: 'User Datagram', ICMP: 'Internet Control Message' }[f.l4_proto] || '') + ')', color: '#f472b6', summary: (f.src_port ? f.src_port : '?') + ' → ' + (f.dst_port ? f.dst_port : '?'), off: '-', rows: rows });
            }

            // Layer 4: Application
            const appRows = [];
            if (f.dns_q) appRows.push([t('pcap_f_dns'), f.dns_q, '-']);
            if (f.sni) appRows.push([t('pcap_f_sni'), f.sni, '-']);
            if (appRows.length) {
                layers.push({ name: f.dns_q ? 'Domain Name System' : 'TLS / Application', color: '#fb923c', summary: f.dns_q || f.sni || '', off: '-', rows: appRows });
            }

            let html = '<div class="pkt-layer-tree-title" data-i18n="pcap_layer_tree">协议分层解析 (Protocol Dissection)</div>';
            for (const L of layers) {
                const rowsHtml = L.rows.map(r =>
                    '<div class="pkt-layer-row">' +
                    '<span class="pkt-layer-row-offset">' + (r[2] || '') + '</span>' +
                    '<span class="pkt-layer-row-key">' + r[0] + ':</span>' +
                    '<span class="pkt-layer-row-val">' + (r[1] === '' || r[1] === 0 || r[1] === '-' ? '-' : r[1]) + '</span>' +
                    '</div>'
                ).join('');
                html += '<details open class="pkt-layer-box">' +
                    '<summary class="pkt-layer-summary" style="color:' + L.color + ';">' +
                    '<span class="pkt-layer-offset">[' + (L.off || '-') + ']</span>' +
                    '<span class="pkt-layer-name">' + L.name + '</span>' +
                    '<span class="pkt-layer-summary-text">' + (L.summary || '') + '</span>' +
                    '</summary>' +
                    '<div class="pkt-layer-body">' + rowsHtml + '</div>' +
                    '</details>';
            }
            return html;
        }

        function closePcapModal() {
            document.getElementById('pcapModal').classList.remove('active');
        }

        async function copyPcapHex() {
            const ta = document.getElementById('pcapModalHex');
            try {
                await navigator.clipboard.writeText(ta.value);
            } catch (e) {
                ta.select();
                document.execCommand('copy');
            }
        }

        // ── Slider progress helper ────────────────────────────────
        // Reads the input's value/min/max and sets a CSS variable --pct on
        // the element so the slider's track can render a filled portion
        // (left of thumb = colored, right of thumb = muted). Called both on
        // every input event and once during openConfigModal() to paint the
        // initial state. Idempotent: no-op if min==max.
        function updateRangeProgress(el) {
            try {
                const min = parseFloat(el.min);
                const max = parseFloat(el.max);
                if (!isFinite(min) || !isFinite(max) || max <= min) return;
                const val = parseFloat(el.value);
                const pct = Math.max(0, Math.min(100, ((val - min) / (max - min)) * 100));
                el.style.setProperty('--pct', pct + '%');
            } catch (_) { /* element gone or unparseable */ }
        }
        window.updateRangeProgress = updateRangeProgress;

        // ── Expose actions for data-on* delegation ────────────────
        // The strict-separation event delegation in this file runs each
        // data-onclick="" expression via `new Function('e', code)`, which
        // executes in the GLOBAL scope — so any callback referenced by
        // data-onclick / data-onchange / data-oninput in index.html MUST be
        // reachable from `window.*`. We make the entire modal/action
        // vocabulary explicit here so future index.html edits can rely on
        // a single, discoverable surface. See theme.js for the same
        // pattern (window.toggleTheme).
        const _exposed = {
            // Settings modal
            openConfigModal, closeConfigModal, saveConfigModal,
            // ACL editor & test
            openACLEditor, closeACLEditor, saveACLEditor,
            openACLTestModal: openACLTestModal, closeACLTest, runACLTest,
            addACLRuleRow, deleteACLRuleRow, updateACLRuleItem, moveACLRuleItem,
            addEditorACLRule, deleteEditorACLRule, updateEditorACLRuleItem,
            moveEditorACLRule, applyACLTemplate,
            // Peer / peer-action modals
            openMultiaddrModal, closeMultiaddrModal, testPeerMultiaddrs,
            openPcapModal, closePcapModal, copyPcapHex, pcapToggle, pcapClear,
            openPeerEncModal, closePeerEncModal, copyPeerEncField,
            openAddStaticPeerModal, closeAddStaticPeerModal, submitAddStaticPeer,
            openPeerDiagnosticsModal, closePeerDiagnosticsModal,
            // Exit / Route / SpeedTest / Share
            openLoginModal, closeLoginModal, submitLogin,
            openSpeedTestModal, closeSpeedTestModal, runSpeedTest,
            inspectRoute, closeRouteInspector,
            openShareModal, closeShareModal, copyConfigJSON, downloadConfigJSON,
            // Obfuscation / form helpers
            onObfsModeChange, updateToggleLabel,
            addCfgListItem, delCfgListItem, moveCfgListItem,
            // Stats / logs / topology toolbar
            fetchStats, setLanguage,
            resetTopologyZoom, autoFitTopology: autoFitTopologyIfNeeded,
            selectTopoFilter, selectTopoNode, clearTopoSelection,
            copySecFingerprint,
            setLogFilter, toggleAutoScroll, toggleLogPause, copyLogConsole, clearLogConsole,
            runPingDiagnostics, runTracerouteDiagnostics, runConnectivityDiagnosis,
        };
        // ── Generic module search / filter with match highlighting ──
        // Every list/table on the dashboard (and several config-modal lists)
        // carries a `.module-search` input with a `data-search-target` pointing
        // at its container. Typing filters direct-child rows by text (case
        // insensitive) and wraps matched substrings in <mark class="search-hl">.
        // A MutationObserver re-applies the active filter whenever the list is
        // re-rendered (live stats poll, WS stream, add/remove), so the highlight
        // survives the constant DOM churn. We disconnect the observer while
        // mutating to avoid feedback loops from the <mark> insertions.
        function debounce(fn, wait) {
            let t = null;
            return function () {
                const ctx = this, args = arguments;
                clearTimeout(t);
                t = setTimeout(function () { fn.apply(ctx, args); }, wait);
            };
        }

        function escapeRegExp(s) {
            return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        }

        function unwrapHighlights(root) {
            const marks = root.querySelectorAll('mark.search-hl');
            Array.prototype.forEach.call(marks, function (m) {
                const t = document.createTextNode(m.textContent);
                if (m.parentNode) m.parentNode.replaceChild(t, m);
            });
            if (root.normalize) root.normalize();
        }

        // Wrap every case-insensitive occurrence of `query` inside `el`'s text
        // nodes (skipping form controls) with a <mark class="search-hl">.
        function highlightInElement(el, query) {
            const lower = query.toLowerCase();
            const re = new RegExp(escapeRegExp(query), 'gi');
            const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, {
                acceptNode: function (node) {
                    const p = node.parentElement;
                    if (!p) return NodeFilter.FILTER_REJECT;
                    const tag = p.tagName;
                    if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'INPUT' ||
                        tag === 'TEXTAREA' || tag === 'SELECT' || tag === 'OPTION') {
                        return NodeFilter.FILTER_REJECT;
                    }
                    if (!node.nodeValue || node.nodeValue.toLowerCase().indexOf(lower) === -1) {
                        return NodeFilter.FILTER_REJECT;
                    }
                    return NodeFilter.FILTER_ACCEPT;
                }
            });
            const targets = [];
            let n;
            while ((n = walker.nextNode())) targets.push(n);
            targets.forEach(function (textNode) {
                const str = textNode.nodeValue;
                const frag = document.createDocumentFragment();
                let last = 0, m;
                re.lastIndex = 0;
                while ((m = re.exec(str)) !== null) {
                    const idx = m.index, mt = m[0];
                    if (idx > last) frag.appendChild(document.createTextNode(str.slice(last, idx)));
                    const mark = document.createElement('mark');
                    mark.className = 'search-hl';
                    mark.textContent = mt;
                    frag.appendChild(mark);
                    last = idx + mt.length;
                    if (mt.length === 0) re.lastIndex++;
                }
                if (last < str.length) frag.appendChild(document.createTextNode(str.slice(last)));
                textNode.parentNode.replaceChild(frag, textNode);
            });
        }

        function applyModuleFilter(container, query) {
            const q = (query || '').trim();
            unwrapHighlights(container);
            const rows = Array.prototype.slice.call(container.children);
            if (!q) {
                rows.forEach(function (r) { r.style.display = ''; });
                return;
            }
            const lower = q.toLowerCase();
            rows.forEach(function (row) {
                const text = (row.textContent || '').toLowerCase();
                if (text.indexOf(lower) !== -1) {
                    row.style.display = '';
                    highlightInElement(row, q);
                } else {
                    row.style.display = 'none';
                }
            });
        }

        function initModuleSearch() {
            const inputs = document.querySelectorAll('.module-search:not([data-paginate])');
            Array.prototype.forEach.call(inputs, function (input) {
                const targetId = input.getAttribute('data-search-target');
                const container = targetId ? document.getElementById(targetId) : null;
                if (!container) return;
                let obs = null;
                const run = function () {
                    if (obs) obs.disconnect();
                    applyModuleFilter(container, input.value);
                    if (obs) obs.observe(container, { childList: true, subtree: true });
                };
                const debounced = debounce(run, 60);
                obs = new MutationObserver(debounced);
                obs.observe(container, { childList: true, subtree: true });
                input.addEventListener('input', debounced);
                // Initial pass — disconnect first so our own mutations don't
                // schedule a redundant re-run.
                obs.disconnect();
                applyModuleFilter(container, input.value);
                obs.observe(container, { childList: true, subtree: true });
            });
        }

        // ── Generic module pagination (filter + page slice) ──
        // For any `.module-search` input flagged with `data-paginate="true"`: reuses
        // the same text-filter + highlight as initModuleSearch, but additionally
        // slices the matching rows into pages (display toggle) and injects a
        // pagination bar after the table. Re-runs on every stats re-render via a
        // childList MutationObserver, so the page survives live updates. Works for
        // any container whose direct children are row elements (<tr> for <tbody>,
        // row <div>s for the encList panel). Page state is kept per table.
        //
        // Optional attribute: `data-paginate-row-selector="<css selector>"` —
        // when set, the controller matches rows via `container.querySelectorAll()`
        // instead of using direct children. Use this when rows are nested inside
        // a wrapper inside the target (e.g. the Exit Gateway panel keeps its
        // candidate cards inside an `.exit-candidates-grid` wrapper so the grid
        // layout survives even when paging). When omitted, rows default to the
        // container's direct element children (`container.children`).
        function initModulePagination() {
            document.querySelectorAll('.module-search[data-paginate]').forEach(function (input) {
                const targetId = input.getAttribute('data-search-target');
                const container = targetId ? document.getElementById(targetId) : null;
                if (!container) return;

                // When `data-paginate-row-selector` is omitted the rows are the
                // container's direct element children. `> *` alone is NOT a valid
                // selector for querySelectorAll (it must be `:scope > *`), so we
                // special-case the default and fall back to `container.children`.
                const rowSelector = input.getAttribute('data-paginate-row-selector');

                const defaultPageSize = parseInt(input.getAttribute('data-paginate-page-size') || input.getAttribute('data-page-size'), 10) || 25;

                // Build + inject the pagination bar right after the table (or after
                // the container itself when there is no enclosing <table>, e.g. encList).
                const bar = document.createElement('div');
                bar.className = 'pagination-bar';
                bar.id = 'pg-' + targetId;
                bar.innerHTML =
                    '<button type="button" class="pg-btn" id="pg-' + targetId + '-prev" data-i18n="prev_page">' + t('prev_page') + '</button>' +
                    '<span class="pg-info" id="pg-' + targetId + '-info">1 / 1</span>' +
                    '<button type="button" class="pg-btn" id="pg-' + targetId + '-next" data-i18n="next_page">' + t('next_page') + '</button>' +
                    '<label class="pg-size"><span data-i18n="per_page">' + t('per_page') + '</span>' +
                    '<select id="pg-' + targetId + '-size">' +
                    '<option value="25"' + (defaultPageSize === 25 ? ' selected' : '') + '>25</option>' +
                    '<option value="50"' + (defaultPageSize === 50 ? ' selected' : '') + '>50</option>' +
                    '<option value="100"' + (defaultPageSize === 100 ? ' selected' : '') + '>100</option>' +
                    '<option value="200"' + (defaultPageSize === 200 ? ' selected' : '') + '>200</option>' +
                    '</select></label>' +
                    '<span class="pg-nomatch" id="pg-' + targetId + '-nomatch" style="display:none;"></span>';
                const tableResp = container.closest('.table-responsive');
                if (tableResp && tableResp.parentNode) {
                    tableResp.parentNode.insertBefore(bar, tableResp.nextSibling);
                } else {
                    const table = container.tagName === 'TBODY' ? container.closest('table') : null;
                    const ref = table ? table : container;
                    const parent = ref.parentNode;
                    if (parent) parent.insertBefore(bar, ref.nextSibling);
                }

                const state = { page: 1, size: defaultPageSize, term: '' };

                const infoEl = document.getElementById('pg-' + targetId + '-info');
                const prevEl = document.getElementById('pg-' + targetId + '-prev');
                const nextEl = document.getElementById('pg-' + targetId + '-next');
                const sizeEl = document.getElementById('pg-' + targetId + '-size');
                const nomatchEl = document.getElementById('pg-' + targetId + '-nomatch');

                let obs = null;
                function apply() {
                    if (obs) obs.disconnect();
                    unwrapHighlights(container);
                    const rows = Array.prototype.slice.call(
                        rowSelector ? container.querySelectorAll(rowSelector) : container.children
                    );
                    const term = state.term;
                    const matched = [];
                    rows.forEach(function (row) {
                        const text = (row.textContent || '').toLowerCase();
                        if (!term || text.indexOf(term) !== -1) {
                            matched.push(row);
                            if (term) highlightInElement(row, term);
                        }
                    });
                    const totalPages = Math.max(1, Math.ceil(matched.length / state.size));
                    if (state.page > totalPages) state.page = totalPages;
                    if (state.page < 1) state.page = 1;
                    const startIdx = (state.page - 1) * state.size;
                    const endIdx = startIdx + state.size;
                    const show = new Set();
                    for (let i = startIdx; i < endIdx && i < matched.length; i++) show.add(matched[i]);
                    rows.forEach(function (row) {
                        row.style.display = show.has(row) ? '' : 'none';
                    });
                    if (infoEl) infoEl.textContent = state.page + ' / ' + totalPages;
                    if (nomatchEl) {
                        if (term && matched.length === 0) {
                            nomatchEl.textContent = t('no_match') + ': ' + input.value;
                            nomatchEl.style.display = '';
                        } else {
                            nomatchEl.style.display = 'none';
                        }
                    }
                    if (prevEl) prevEl.disabled = state.page <= 1;
                    if (nextEl) nextEl.disabled = state.page >= totalPages;
                    if (obs) obs.observe(container, { childList: true });
                }

                // Microtask synchronous apply on DOM changes prevents rendering unpaged rows before paint
                obs = new MutationObserver(apply);
                obs.observe(container, { childList: true });

                const debouncedInput = debounce(apply, 80);
                input.addEventListener('input', function () {
                    state.term = (input.value || '').trim().toLowerCase();
                    state.page = 1;
                    debouncedInput();
                });

                if (prevEl) prevEl.addEventListener('click', function () { if (state.page > 1) { state.page--; apply(); } });
                if (nextEl) nextEl.addEventListener('click', function () { state.page++; apply(); });
                if (sizeEl) sizeEl.addEventListener('change', function () { state.size = parseInt(sizeEl.value, 10) || 50; state.page = 1; apply(); });

                // Initial pass (container may still be empty before first stats tick).
                apply();
            });
        }

        // ── Mouse Drag-to-Scroll for all .table-responsive containers ──
        function initTableDragScroll() {
            document.querySelectorAll('.table-responsive').forEach(function (slider) {
                if (slider._dragScrollInit) return;
                slider._dragScrollInit = true;

                let isDown = false;
                let startX = 0;
                let scrollLeft = 0;
                let isDragging = false;

                slider.addEventListener('mousedown', function (e) {
                    if (e.button !== 0 || e.target.closest('button, input, select, a, textarea, [data-onclick], label, .btn, .btn-glass')) {
                        return;
                    }
                    isDown = true;
                    isDragging = false;
                    startX = e.pageX - slider.offsetLeft;
                    scrollLeft = slider.scrollLeft;
                    slider.style.cursor = 'grabbing';
                    slider.style.userSelect = 'none';
                });

                const endDrag = function () {
                    if (!isDown) return;
                    isDown = false;
                    slider.style.cursor = '';
                    slider.style.removeProperty('user-select');
                    if (isDragging) {
                        const clickBlocker = function (ev) {
                            ev.stopPropagation();
                            ev.preventDefault();
                            window.removeEventListener('click', clickBlocker, true);
                        };
                        window.addEventListener('click', clickBlocker, true);
                        setTimeout(function () {
                            window.removeEventListener('click', clickBlocker, true);
                            isDragging = false;
                        }, 50);
                    }
                };

                window.addEventListener('mouseup', endDrag);
                slider.addEventListener('mouseleave', endDrag);

                slider.addEventListener('mousemove', function (e) {
                    if (!isDown) return;
                    e.preventDefault();
                    const x = e.pageX - slider.offsetLeft;
                    const walk = (x - startX) * 1.5;
                    if (Math.abs(walk) > 3) {
                        isDragging = true;
                    }
                    slider.scrollLeft = scrollLeft - walk;
                });
            });
        }

        Object.assign(window, _exposed);

        // Initialize i18n Language & Start Stats/Logs Loop
        setLanguage(currentLang);
        initModuleSearch();
        // Generic per-table pagination for the large data lists (peers, peer-meta,
        // routes, ARP, MAC, per-peer encryption). Auto-injects its own bar.
        initModulePagination();
        // Enable mouse click & drag horizontal scrolling for all wide tables (static + dynamically opened modals)
        initTableDragScroll();
        const dragScrollObserver = new MutationObserver(debounce(initTableDragScroll, 80));
        dragScrollObserver.observe(document.body, { childList: true, subtree: true });

        // IP Traffic Analytics: self-contained pagination + search (decoupled
        // from the generic .module-search MutationObserver so paging works).
        (function initIpPagination() {
            const ipSearchEl = document.querySelector('.ip-search');
            if (ipSearchEl) ipSearchEl.addEventListener('input', debounce(renderIpTable, 80));
            const ipPrevEl = document.getElementById('ipPrev');
            const ipNextEl = document.getElementById('ipNext');
            const ipSizeEl = document.getElementById('ipPageSize');
            if (ipPrevEl) ipPrevEl.addEventListener('click', function () { if (ipCurPage > 1) { ipCurPage--; renderIpTable(); } });
            if (ipNextEl) ipNextEl.addEventListener('click', function () { ipCurPage++; renderIpTable(); });
            if (ipSizeEl) ipSizeEl.addEventListener('change', function () { ipPageSize = parseInt(ipSizeEl.value, 10) || 50; ipCurPage = 1; renderIpTable(); });
        })();
        // Protocol Streams search: re-render on each keystroke using cached data.
        (function initStreamSearch() {
            const el = document.getElementById('streamSearchInput');
            if (el) el.addEventListener('input', debounce(function () {
                if (window.__lastStatsData) renderProtocolChannels(window.__lastStatsData);
            }, 100));
        })();
        updateLogFilterUI();
        updateLogPauseUI();
        setInterval(fetchStats, 2000);
        setInterval(pcapRefreshState, 1500);

        // Packet frames and the live log are now streamed over WebSockets.
        // pcapStream.connect() / logStream.connect() are idempotent and
        // self-healing; each falls back to its legacy HTTP poller automatically
        // if six reconnect attempts fail.
        pcapStream.connect();
        // Logs stream incrementally (only NEW lines are sent) instead of the
        // old full-refetch-every-2.5s poll; fetchLogs() remains the HTTP
        // fallback used by logStream once the WebSocket gives up.
        logStream.connect();
        // Show the login gate up-front when no token is stored, instead of
        // waiting for the first 401. The stored token (if any) is pre-filled.
        if (!getAuthToken()) {
            openLoginModal();
        }

        // ACL card toolbar buttons (open editor / test rule).
        const _aclEditBtn = document.getElementById('aclEditBtn');
        if (_aclEditBtn) _aclEditBtn.addEventListener('click', () => { try { addACLRuleRow(); } catch (_) {} openACLEditor(); });
        const _aclTestBtn = document.getElementById('aclTestBtn');
        if (_aclTestBtn) _aclTestBtn.addEventListener('click', openACLTestModal);

        fetchStats();
        pcapRefreshState();
        startTopologyLoop();   // continuous 60fps particle animation
        document.addEventListener('visibilitychange', function () {
            // Restart the rAF loop when returning to the tab.
            if (!document.hidden && topoRAFId === null) startTopologyLoop();
            // Browsers will close backgrounded sockets after a while; when the
            // user returns, force-reconnect the packet stream so subsequent
            // captures show up immediately rather than after the dead socket
            // is finally garbage-collected.
            if (!document.hidden) pcapStream.connect();
            // Browsers also close backgrounded log sockets; force-reconnect on
            // return so new log lines show up immediately.
            if (!document.hidden) logStream.connect();
        });
        fetchLogs();
        window.addEventListener('resize', function() {
            drawTopologyMesh();
            if (bwChartState.history.length) drawBandwidthChart(bwChartState.history);
            if (ppsChartState.history.length) drawPacketRateChart(ppsChartState.history);
        });
    
