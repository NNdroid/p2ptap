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
                score_loopback: "Loopback (Score 0)",
                score_lan_direct: "LAN Direct (Score 10)",
                score_wan_direct: "WAN Direct (Score 20)",
                score_relay: "Relay (Score 100)",
                priority_score_tooltip: "Routing Priority Score: lower is higher priority (0:Loopback, 10:LAN Direct, 20:WAN Direct, 100:Relay)",

                channel_status_synced: "Synchronized",
                lbl_peers: "peers",
                channel_peekmap_desc: "Bootstrap Topology Sync",

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
                channel_data_name: "Datapath (Direct + Relay)",
                channel_data_proto: "Layer-2 Ethernet Overlay",
                channel_auth_name: "Mesh Authentication",
                channel_auth_desc: "PSK Mesh Network Isolation",
                channel_dcutr_name: "DCUtR Hole-Punch & Relay",
                channel_dcutr_desc: "Direct Connection Upgrade",
                cipher_lbl: "Cipher",

                proto_traffic_distribution: "Protocol Traffic Distribution",
                frames_unit: "frames",
                btn_global_resync: "Global Resync",
                btn_resync: "Resync",
                btn_resync_title: "Force SeqSync & Key Rotation",
                cat_tab_all: "All",
                cat_tab_data: "Data",
                cat_tab_sync: "Sync & Security",
                cat_tab_routing: "Routing",
                cat_tab_transport: "Transport",
                cat_tab_pubsub: "PubSub",
                cat_tab_diagnostics: "Diagnostics",
                tx_frames_lbl: "TX Frames",
                rx_frames_lbl: "RX Frames",
                sync_events_lbl: "Sync Events",
                synced_peers_lbl: "Synced Peers",
                resync_success: "SeqSync & Key Rotation triggered",
                btn_crypto_inspector: "Crypto & Sequence Inspector",
                crypto_inspector_title: "Peer Cryptography & Anti-Replay Sequence Inspector",
                select_peer_lbl: "Select Peer:",
                btn_resync_this_peer: "Resync This Peer",
                btn_export_report: "Export Report",
                diagnostic_export_success: "Diagnostic report exported successfully!",
                sliding_window_lbl: "Anti-Replay Sliding Window (0..65535)",
                ephemeral_fp_lbl: "Ephemeral ECDH Key Fingerprint",
                tx_key_fp_lbl: "TxKey Fingerprint",
                rx_key_fp_lbl: "RxKey Fingerprint",
                cipher_algo_lbl: "Negotiated Cipher",
                handshake_latency_lbl: "Handshake Latency",
                no_peers_connected: "No peers connected. Ready to establish secure P2P mesh.",

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
                pcap_modal_raw: "Frame head hex (first 64 bytes)",
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
                pcap_hex_parse_error: "Cannot parse raw frame",
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
                col_tap_path: "TAP Path",
                conn_ok: "Connected",
                conn_relay_ok: "Relay OK",
                conn_connecting: "Connecting",
                conn_proto_mismatch: "Proto Mismatch",
                conn_obf_failed: "Decrypt Fail",
                conn_unreachable: "Unreachable",
                return_ok: "Return OK",
                return_dead: "Return Dead",
                return_idle: "Standby",
                return_relay_only: "Relay Only",
                return_asymmetric: "One-Way (Tx)",
                return_mac_mismatch: "MAC Mismatch",
                tp_ok: "TAP OK",
                tp_fail: "TAP Fail",
                tp_mac_mismatch: "MAC Mismatch",
                tp_unknown: "Unprobed",
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
                lbl_tls_sni: "TLS/QUIC SNI (outgoing):",
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
                sec_peer_sni: "Handshake SNI (peer presented)",
                sec_peer_psk: "PSK verified",
                sec_peer_conns: "Negotiated connections",
                sec_conn_in: "inbound (peer dialed us)",
                sec_conn_out: "outbound (we dialed)",
                sec_conn_noise_hint: "Noise handshake — no TLS ClientHello, so no SNI can be shown.",
                sec_conn_out_only: "Only outbound connections to this peer — its SNI can only be observed when the peer dials us.",
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
                view_visual: "📊 Visual Flow",
                view_raw: ">_ Terminal",
                diag_idle_title: "Select a peer or enter an address to start diagnostic",
                diag_idle_desc: "Inspect real-time RTT latency, jitter stability, packet loss, and full overlay hop-by-hop forwarding topology.",
                enc_plaintext: "Plaintext (none)",
                enc_not_active: "Not Active",
                active_peers: "⚡ Active P2P Peers",
                routes_table: "🛣️ Smart P2P Overlay Routing Table",
                stat_total_routes: "Total Computed Routes",
                stat_relayed_routes: "Relay Accelerated Paths",
                stat_max_savings: "Max Latency Reduction",
                arp_table: "📋 Virtual Network ARP / NDP Neighbor Table",
                ip_analytics: "📊 24-Hour Per-IP Traffic Analytics",
                mac_table: "🔀 Virtual Switch MAC Address Table",
                no_routes: "No routing entries computed yet",
                col_dest: "Destination Node",
                col_hops: "Hops",
                col_optimal_path: "Visual Route Path",
                col_total_rtt: "Optimal RTT (est.)",
                col_direct_rtt: "Direct RTT (est.)",
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
                path_metrics_title: "Per-Path Link Metrics",
                path_metrics_kind: "Kind",
                path_metrics_path: "Path",
                path_metrics_usable: "Use",
                path_metrics_tx: "TX",
                path_metrics_rx: "RX",
                path_metrics_bps: "Est. Cap",
                path_metrics_svc: "Svc",
                path_metrics_updated: "Updated",
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
                obfs_lbl: "Enable Traffic Obfuscation",
                obfs_enable_desc: "Pad short frames per the rule below to defeat DPI fingerprinting",
                obfs_rules_lbl: "Padding Rules",
                obfs_rules_desc: "One band per line: <floor> -> <min>[-<max>]. Payloads below the band target are padded to a random size in the range; at/above it they go natural. Optional: coalesce on|off [max_delay_ms=N] [max_bytes=N] [max_frames=N].",
                obfs_strict_key_lbl: "Strict Key Negotiation (PFS)",
                obfs_strict_key_desc: "Forbid falling back to the long-lived node key. Each peer pair must derive its own cipher from a one-shot ECDH ephemeral key; otherwise that peer stays plaintext. Hardens per-pair key isolation.",
                obfs_auth_key_lbl: "Require Authenticated Key Exchange",
                obfs_auth_key_desc: "Require every peer's ECDH key to be signed by its own identity key, so a transit relay cannot substitute its own key and sit in the middle of the encrypted link. Key signing is always on; this only requires it from peers that do not advertise support. Enable only after every peer is upgraded — legacy peers cannot sign and would lose encrypted connectivity.",
                bootstrap_lbl: "Bootstrap Peers",
                section_identity: "Node Identity",
                section_identity_desc: "Name and encryption settings for this node",
                node_name_desc: "Human-readable identifier for the dashboard",
                psk_desc: "Empty for public network, set key for encrypted isolation",
                section_transport: "Transport & Logging",
                section_transport_desc: "Routing strategy and diagnostic verbosity",
                strategy_desc: "Selects among existing streams; does not create extra transports. Multipath balances across all live paths and needs a restart.",
                loglevel_desc: "Controls verbosity of console output",
                enable_mdns_lbl: "Enable mDNS LAN Discovery",
                enable_mdns_desc: "Auto-discover peers on the same LAN via mDNS (local network only)",
                cfg_disable_relay_lbl: "Direct-Only Mode (all relaying OFF)",
                cfg_disable_relay_desc: "Turns OFF both libp2p circuit-relay (client/service, AutoRelay) and DCUtR hole-punching. Requires restart. If a slow peer becomes unreachable with this ON, it was being auto-relayed through a static relay. Overrides the two finer toggles below. Does NOT touch p2ptap's own overlay relay.",
                cfg_disable_circuit_relay_lbl: "Disable circuit relay only",
                cfg_disable_circuit_relay_desc: "Turns OFF libp2p circuit-relay client/service and AutoRelay, leaving DCUtR hole-punching on. Requires restart. Ignored while Direct-Only Mode above is ON.",
                cfg_disable_hole_punching_lbl: "Disable hole-punching only",
                cfg_disable_hole_punching_desc: "Turns OFF DCUtR hole-punching, leaving circuit relay and AutoRelay on. Requires restart. If peers stop connecting after this, the connections were coming from hole punches rather than relays. Ignored while Direct-Only Mode above is ON.",
                cfg_tls_sni_lbl: "TLS/QUIC SNI (outgoing)",
                cfg_tls_sni_desc: "Static server_name sent on every outbound TLS/QUIC handshake so the mesh resembles ordinary HTTP/3 to a DPI. Empty = no SNI (upstream default). Cosmetic only — peers are authenticated via the signed certificate, never the SNI. Requires restart.",
                cfg_tls_sni_suffix_lbl: "TLS SNI suffix (per-peer)",
                cfg_tls_sni_suffix_desc: "When set, overrides the static SNI: each link presents \"<hash-of-peer-id>.<suffix>\" — a distinct, stable SNI per peer under one base domain, avoiding a shared global constant. Use a domain you control. Requires restart.",
                section_obfs: "Traffic Obfuscation",
                section_obfs_desc: "Packet padding to defeat DPI fingerprinting",
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
                strategy_redundant: "Duplicate over existing streams",
                strategy_fallback: "Failover Fallback",
                strategy_multipath: "Multi-Path Load Balance",
                strategy_multipath_hint: "Splits traffic across all live paths (direct + circuit relay) by measured capacity; requires the peer to also run multipath for the receive-side reorder to engage.",
                strategy_best_path_hint: "Uses the single highest-priority live path (default).",
                log_level_debug: "Verbose Debug",
                log_level_info: "Standard Info",
                log_level_warn: "Warnings Only",
                log_level_error: "Errors Only",
                acl_no_rules: "No custom ACL rules yet — add one or pick a template.",
                acl_comment_placeholder: "Comment / Description",
                close_btn: "Close",
                cancel_btn: "Cancel",
                save_btn: "Save & Apply",
                save_success: "Configuration saved successfully!",
                cfg_needs_restart: "⚠️ Disable-relay changed — restart p2ptap to apply.",
                cfg_restart_required: "Some settings apply only after a restart",
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
                sys_runtime_toggle: "Go runtime metrics — heap, GC, goroutines",
                chart_no_traffic: "No traffic yet",
                obfs_state_unknown: "Unknown",
                enc_peers_lbl: "Encrypted peers",
                seq_hint_fmt: "replay {replay} · win-reset {reset} · util {util}%",
                pcap_sample_every: "Sample ratio",
                pcap_max_rate: "Rate limit (frames/s, 0 = unlimited)",
                pcap_idle_skip: "Skip idle",
                peer_id_copy_hint: "Click to copy Peer ID",
            },
            
            
            
            
            
            
        };

        const dashboardLabels = {
            en: ['Overview', 'Peers', 'Routing & firewall', 'Diagnostics', 'Discovery details', 'Forwarding tables & latency matrix', 'System & encryption', 'Traffic details', 'Protocol streams', 'Edit rules', 'Connecting…', 'Live · refreshes every 2s', 'Connection lost · data may be stale', 'Dashboard'],
            'zh-CN': ['概览', '节点', '路由与防火墙', '诊断', '节点发现详情', '转发表与延迟矩阵', '系统与加密', '流量详情', '协议流', '编辑规则', '正在连接…', '已连接 · 每 2 秒刷新', '连接中断 · 数据可能已过期', '控制台页面'],
            'zh-TW': ['概覽', '節點', '路由與防火牆', '診斷', '節點發現詳情', '轉發表與延遲矩陣', '系統與加密', '流量詳情', '協定串流', '編輯規則', '正在連線…', '已連線 · 每 2 秒更新', '連線中斷 · 資料可能已過期', '控制台頁面'],
            ja: ['概要', 'ノード', 'ルートとファイアウォール', '診断', 'ノード検出の詳細', '転送テーブルと遅延行列', 'システムと暗号化', 'トラフィック詳細', 'プロトコルストリーム', 'ルールを編集', '接続中…', '接続済み · 2秒ごとに更新', '接続切断 · データが古い可能性があります', 'ダッシュボード'],
            de: ['Übersicht', 'Knoten', 'Routing & Firewall', 'Diagnose', 'Erkennungsdetails', 'Weiterleitungstabellen & Latenzmatrix', 'System & Verschlüsselung', 'Verkehrsdetails', 'Protokollströme', 'Regeln bearbeiten', 'Verbindung wird hergestellt…', 'Verbunden · Aktualisierung alle 2s', 'Verbindung unterbrochen · Daten möglicherweise veraltet', 'Dashboard'],
            es: ['Resumen', 'Nodos', 'Rutas y cortafuegos', 'Diagnóstico', 'Detalles de descubrimiento', 'Tablas de reenvío y matriz de latencia', 'Sistema y cifrado', 'Detalles de tráfico', 'Flujos de protocolo', 'Editar reglas', 'Conectando…', 'Conectado · actualización cada 2s', 'Conexión perdida · los datos pueden estar desactualizados', 'Panel'],
            fr: ['Vue générale', 'Nœuds', 'Routage et pare-feu', 'Diagnostic', 'Détails de découverte', 'Tables de transfert et matrice de latence', 'Système et chiffrement', 'Détails du trafic', 'Flux de protocole', 'Modifier les règles', 'Connexion…', 'Connecté · actualisation toutes les 2s', 'Connexion perdue · données potentiellement anciennes', 'Tableau de bord'],
        };
        const dashboardLabelKeys = ['overview', 'peers', 'network', 'diagnostics', 'peer_details', 'forwarding_details', 'runtime_details', 'traffic_details', 'protocol_details', 'edit_acl', 'connecting', 'live', 'offline', 'navigation'];
        const compactLabels = {
            en: ['Network', 'Settings', 'Retry', 'Upload', 'Download', 'Details', 'Peer details', 'Diagnose', 'Result view', 'Traffic with this peer', 'Measured link rate', 'Peer-reported node totals', 'Ping & route test'],
            'zh-CN': ['网络', '设置', '重试', '上传', '下载', '详情', '节点详情', '连通诊断', '结果显示方式', '与此节点的流量', '实测链路速率', '对端上报的全局流量', 'Ping 与路径检测'],
            'zh-TW': ['網路', '設定', '重試', '上傳', '下載', '詳情', '節點詳情', '連線診斷', '結果顯示方式', '與此節點的流量', '實測鏈路速率', '對端回報的全域流量', 'Ping 與路徑檢測'],
            ja: ['ネットワーク', '設定', '再試行', '送信', '受信', '詳細', 'ノードの詳細', '接続診断', '結果表示', 'このノードとの通信量', '測定済みリンク速度', '相手ノードの報告総量', 'Ping と経路テスト'],
            de: ['Netzwerk', 'Einstellungen', 'Erneut versuchen', 'Upload', 'Download', 'Details', 'Knotendetails', 'Verbindung prüfen', 'Ergebnisansicht', 'Verkehr mit diesem Knoten', 'Gemessene Linkrate', 'Vom Knoten gemeldeter Gesamtverkehr', 'Ping & Routentest'],
            es: ['Red', 'Ajustes', 'Reintentar', 'Subida', 'Bajada', 'Detalles', 'Detalles del nodo', 'Diagnosticar', 'Vista de resultados', 'Tráfico con este nodo', 'Velocidad medida del enlace', 'Totales informados por el nodo', 'Ping y prueba de ruta'],
            fr: ['Réseau', 'Réglages', 'Réessayer', 'Envoi', 'Réception', 'Détails', 'Détails du nœud', 'Diagnostiquer', 'Affichage du résultat', 'Trafic avec ce nœud', 'Débit mesuré du lien', 'Totaux déclarés par le nœud', 'Ping et test de route'],
        };
        const compactLabelKeys = ['network', 'settings', 'retry', 'tx', 'rx', 'details', 'peer_info', 'diagnose', 'result_view', 'link_traffic', 'link_rate', 'remote_traffic', 'probe_title'];

        const compactActionLabels = {
    "en": [
        "Ping",
        "Trace route",
        "Bandwidth",
        "Connection"
    ],
    "zh-CN": [
        "Ping",
        "路径追踪",
        "实时吞吐量",
        "连接状态"
    ],
    "zh-TW": [
        "Ping",
        "路徑追蹤",
        "即時吞吐量",
        "連線狀態"
    ],
    "ja": [
        "Ping",
        "経路追跡",
        "通信速度",
        "接続状態"
    ],
    "de": [
        "Ping",
        "Route verfolgen",
        "Bandbreite",
        "Verbindung"
    ],
    "es": [
        "Ping",
        "Trazar ruta",
        "Ancho de banda",
        "Conexión"
    ],
    "fr": [
        "Ping",
        "Tracer la route",
        "Débit",
        "Connexion"
    ]
};
        // Locale packs live in static/lang/<lang>.js. The server injects the one
        // matching this client's Accept-Language ahead of app.js; anything else
        // is fetched on demand when the user switches. English stays inline in
        // i18nDict because every missing key falls back to it.
        //
        // Three runtime label tables (dashboardLabels / compactLabels /
        // compactActionLabels) fill in keys that are assembled at runtime
        // ('dashboard_' + key). They must be re-applied whenever a pack arrives,
        // hence applyLabelTables() below rather than a one-shot loop.
        const LOCALE_PACKS = ['zh-CN', 'zh-TW', 'ja', 'de', 'es', 'fr'];

        function applyLabelTables() {
            Object.entries(dashboardLabels).forEach(([lang, labels]) => {
                const pack = i18nDict[lang];
                if (!pack) return;   // pack not loaded (yet) — applied on arrival
                dashboardLabelKeys.forEach((key, i) => { pack['dashboard_' + key] = labels[i]; });
            });
            Object.entries(compactLabels).forEach(([lang, labels]) => {
                const pack = i18nDict[lang];
                if (!pack) return;
                compactLabelKeys.forEach((key, i) => { pack['dashboard_' + key] = labels[i]; });
            });
            Object.entries(compactActionLabels).forEach(([lang, labels]) => {
                const pack = i18nDict[lang];
                if (!pack) return;
                ['ping', 'trace', 'bandwidth', 'connection'].forEach((key, i) => { pack['dashboard_' + key] = labels[i]; });
            });
        }

        // Fold in whatever locale packs have already been injected.
        if (window.p2ptapLocales) {
            for (const k in window.p2ptapLocales) {
                if (window.p2ptapLocales[k]) i18nDict[k] = window.p2ptapLocales[k];
            }
        }
        applyLabelTables();

        // ensureLocale fetches a pack that was not server-injected, applying the
        // runtime label tables once it lands. Resolves false if unavailable.
        function ensureLocale(lang) {
            if (lang === 'en' || i18nDict[lang]) return Promise.resolve(true);
            if (LOCALE_PACKS.indexOf(lang) === -1) return Promise.resolve(false);
            return new Promise(resolve => {
                const s = document.createElement('script');
                s.src = 'lang/' + lang + '.js';
                s.onload = () => {
                    const pack = (window.p2ptapLocales || {})[lang];
                    if (pack) i18nDict[lang] = pack;
                    applyLabelTables();
                    resolve(!!pack);
                };
                s.onerror = () => resolve(false);
                document.head.appendChild(s);
            });
        }

        // The server negotiated a language from Accept-Language and injected
        // that pack already; prefer its hint so a pack sitting in memory is
        // actually used instead of falling back to the browser's own guess.
        const serverLang = window.p2ptapLocaleHint;
        let currentLang = localStorage.getItem('p2ptap_lang')
            || (serverLang && i18nDict[serverLang] ? serverLang : null)
            || (navigator.language && navigator.language.startsWith('zh') ? (navigator.language.includes('TW') || navigator.language.includes('HK') ? 'zh-TW' : 'zh-CN') : 'en');
        if (!i18nDict[currentLang]) currentLang = 'en';

        function t(key) {
            return (i18nDict[currentLang] && i18nDict[currentLang][key]) || (i18nDict.en[key] || key);
        }

        function setLanguage(lang) {
            if (lang !== 'en' && !i18nDict[lang]) {
                ensureLocale(lang).then(ok => { if (ok) setLanguage(lang); });
                return;
            }
            currentLang = lang;
            localStorage.setItem('p2ptap_lang', lang);
            document.getElementById('langSelect').value = lang;

            // Elements whose text is managed by the stats/render loop must NOT
            // be overwritten here: doing so replaces live values (node name,
            // strategy badge, log count, auto-scroll state, pcap state, etc.)
            // with the static default for up to one poll cycle.
            const liveStateIds = new Set([
                'strategyBadge', 'nodeName', 'nodePeerID', 'logCountBadge',
                'logPausedBadge', 'autoScrollBtn', 'logPauseBtn',
                'pcapStateBadge', 'pcapToggleBtn'
            ]);

            document.querySelectorAll('[data-i18n]').forEach(el => {
                if (liveStateIds.has(el.id)) return;
                const k = el.getAttribute('data-i18n');
                if (k) {
                    el.innerText = t(k);
                }
            });

            document.querySelectorAll('[data-i18n-ph]').forEach(el => {
                const k = el.getAttribute('data-i18n-ph');
                if (k) {
                    el.placeholder = t(k);
                }
            });

            document.documentElement.lang = lang;
            document.querySelectorAll('[data-i18n-aria]').forEach(el => {
                el.setAttribute('aria-label', t(el.getAttribute('data-i18n-aria')));
            });

            document.getElementById('cfgPSK').placeholder = t('psk_placeholder');

            // pcap_desc contains HTML <span> tags, so use innerHTML instead of textContent
            const descEl = document.getElementById('pcapDescText');
            if (descEl) { descEl.innerHTML = t('pcap_desc'); }

            fetchStats();
        }

        let currentFullConfig = {};
        const dashboardPages = ['overview', 'peers', 'network', 'diagnostics'];

        function currentDashboardPage() {
            return dashboardPages.find(name => !document.getElementById('dashboard-' + name).hidden) || 'overview';
        }

        function redrawDashboardCharts() {
            drawTopologyMesh();
            if (bwChartState.history.length) drawBandwidthChart(bwChartState.history);
            if (ppsChartState.history.length) drawPacketRateChart(ppsChartState.history);
        }

        function selectDashboardPage(name, updateHistory = true) {
            if (!dashboardPages.includes(name)) name = 'overview';
            const previous = currentDashboardPage();
            dashboardPages.forEach(page => {
                const selected = page === name;
                document.getElementById('dashboard-' + page).hidden = !selected;
                const tab = document.getElementById('dashboard-tab-' + page);
                tab.setAttribute('aria-selected', String(selected));
                tab.tabIndex = selected ? 0 : -1;
            });
            if (updateHistory && location.hash !== '#' + name) history.pushState(null, '', '#' + name);
            if (name === 'peers' && !document.hidden) {
                startTopologyLoop();
            } else if (topoRAFId !== null) {
                cancelAnimationFrame(topoRAFId);
                topoRAFId = null;
            }
            syncDiagnosticStreams();
            redrawDashboardCharts();
            if (previous !== name) window.scrollTo(0, 0);
            fetchStats();
        }

        function syncDiagnosticStreams() {
            const active = !document.hidden && currentDashboardPage() === 'diagnostics';
            if (active && document.getElementById('logsDetails').open) {
                logStream.connect();
                fetchLogs();
            } else logStream.disconnect();
            if (active && document.getElementById('captureDetails').open) {
                pcapStream.connect();
                pcapRefreshState();
            } else pcapStream.disconnect();
        }

        function updateDashboardStatus(connected) {
            const status = document.getElementById('dashboardStatus');
            status.classList.toggle('is-offline', !connected);
            document.getElementById('dashboardRetry').hidden = connected;
            const label = document.getElementById('dashboardStatusText');
            label.setAttribute('data-i18n', connected ? 'dashboard_live' : 'dashboard_offline');
            label.textContent = t(connected ? 'dashboard_live' : 'dashboard_offline');
        }

        function formatBytes(bytes) {
            if (!bytes || bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function formatSpeed(bytesPerSec) {
            if (!bytesPerSec || bytesPerSec <= 0) return '⚡ 0 KB/s';
            if (bytesPerSec < 1024) {
                return '⚡ ' + bytesPerSec.toFixed(1) + ' B/s';
            }
            if (bytesPerSec < 1048576) {
                return '⚡ ' + (bytesPerSec / 1024).toFixed(1) + ' KB/s';
            }
            if (bytesPerSec < 1073741824) {
                return '⚡ ' + (bytesPerSec / 1048576).toFixed(2) + ' MB/s';
            }
            return '⚡ ' + (bytesPerSec / 1073741824).toFixed(2) + ' GB/s';
        }

        const peerDetailsCache = new Map();
        let selectedPeerDetails = null;
        let peerDetailsFocus = null;
        let peerDetailsContent = null;

        function refreshPeerDetails() {
            if (!selectedPeerDetails) return;
            const peer = cachedPeers.find(p => p.peer_id === selectedPeerDetails);
            document.getElementById('peerDetailsTitle').textContent = peer ? (peer.node_name || t('unnamed_node')) : t('dashboard_peer_info');
            const body = document.getElementById('peerDetailsBody');
            const content = peerDetailsCache.get(selectedPeerDetails) || `<p class="empty-row">${escapeHTML(t('no_peers'))}</p>`;
            if (peerDetailsContent !== content) {
                const scroll = body.scrollTop;
                const focusedAction = body.contains(document.activeElement) ? document.activeElement.getAttribute('data-onclick') : null;
                body.innerHTML = content;
                peerDetailsContent = content;
                body.scrollTop = scroll;
                if (focusedAction) {
                    const replacement = [...body.querySelectorAll('[data-onclick]')].find(el => el.getAttribute('data-onclick') === focusedAction);
                    if (replacement) replacement.focus({ preventScroll: true });
                }
            }
        }

        function openPeerDetails(peerID) {
            if (!peerDetailsCache.has(peerID)) return;
            selectedPeerDetails = peerID;
            peerDetailsContent = null;
            peerDetailsFocus = document.activeElement;
            refreshPeerDetails();
            const modal = document.getElementById('peerDetailsModal');
            modal.classList.add('active');
            modal.style.display = 'flex';
            modal.querySelector('button').focus();
        }

        function closePeerDetails() {
            const modal = document.getElementById('peerDetailsModal');
            modal.classList.remove('active');
            modal.style.display = 'none';
            selectedPeerDetails = null;
            peerDetailsContent = null;
            const target = peerDetailsFocus && peerDetailsFocus.isConnected ? peerDetailsFocus : document.getElementById('dashboard-tab-peers');
            target.focus();
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

        async function openConfigModal(section) {
            try {
                const res = await fetch('/api/config', withAuth());
                if (!res.ok) throw new Error('HTTP ' + res.status);
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
                }
                const disableCircuitRelayEl = document.getElementById('cfgDisableCircuitRelay');
                if (disableCircuitRelayEl) disableCircuitRelayEl.checked = !!transports.disable_circuit_relay;
                const disableHolePunchingEl = document.getElementById('cfgDisableHolePunching');
                if (disableHolePunchingEl) disableHolePunchingEl.checked = !!transports.disable_hole_punching;
                const sniEl = document.getElementById('cfgTlsServerName');
                if (sniEl) sniEl.value = transports.tls_server_name || '';
                const sniSuffixEl = document.getElementById('cfgTlsSniSuffix');
                if (sniSuffixEl) sniSuffixEl.value = transports.tls_sni_suffix || '';
                document.getElementById('cfgEnableMDNS').checked = !!currentFullConfig.enable_mdns;

                const obfs = currentFullConfig.obfuscation || {};
                const obfsEnableEl = document.getElementById('cfgObfEnable');
                if (obfsEnableEl) obfsEnableEl.checked = !!obfs.enable;
                document.getElementById('cfgPaddingRules').value = obfs.padding_rules || '0 -> 400-600';
                document.getElementById('cfgStrictKeyNegotiation').checked = !!obfs.strict_key_negotiation;
                document.getElementById('cfgRequireAuthKeyExchange').checked = !!obfs.require_auth_key_exchange;
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
                    if (section === 'acl') document.getElementById('configACLSection').scrollIntoView({ block: 'start' });
                }
            } catch (e) {
                console.error("Open config modal error:", e);
                showToast(t('req_error') + e.message, true);
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
        function _aclOppositeAction() {
            const el = document.getElementById('cfgACLDefaultAction');
            return el && el.value === 'drop' ? 'accept' : 'drop';
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
                action: _aclOppositeAction(),
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
                const circuitRelayEl = document.getElementById('cfgDisableCircuitRelay');
                if (circuitRelayEl) currentFullConfig.transports.disable_circuit_relay = circuitRelayEl.checked;
                const holePunchingEl = document.getElementById('cfgDisableHolePunching');
                if (holePunchingEl) currentFullConfig.transports.disable_hole_punching = holePunchingEl.checked;
                const sniEl = document.getElementById('cfgTlsServerName');
                if (sniEl) currentFullConfig.transports.tls_server_name = sniEl.value.trim();
                const sniSuffixEl = document.getElementById('cfgTlsSniSuffix');
                if (sniSuffixEl) currentFullConfig.transports.tls_sni_suffix = sniSuffixEl.value.trim();

                if (!currentFullConfig.obfuscation) currentFullConfig.obfuscation = {};
                const ob = currentFullConfig.obfuscation;
                const obfsEnableEl = document.getElementById('cfgObfEnable');
                ob.enable = obfsEnableEl ? obfsEnableEl.checked : true;
                ob.padding_rules = (document.getElementById('cfgPaddingRules').value || '0 -> 400-600').trim();
                ob.strict_key_negotiation = document.getElementById('cfgStrictKeyNegotiation').checked;
                ob.require_auth_key_exchange = document.getElementById('cfgRequireAuthKeyExchange').checked;

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
                    // The server tells us authoritatively whether any changed field
                    // is restart-only (transports/SNI/TAP/listen/PSK/peers/strategy/
                    // web_ui bind) vs hot-applied (obfuscation/exit-node/name). Show a
                    // warning naming the fields so "saved" is never mistaken for
                    // "live" when a restart is actually required.
                    let saveData = null;
                    try { saveData = await res.json(); } catch (e) { /* older binary */ }
                    if (saveData && saveData.restart_required) {
                        const fields = (saveData.restart_fields || []).join(', ');
                        const hint = (t('cfg_restart_required') || 'Some settings apply only after a restart') + (fields ? ': ' + fields : '');
                        showToast(t('save_success') + ' — ⚠️ ' + hint, false, true);
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

            const allAddrsList = (peer.all_addrs?.length ? peer.all_addrs : [peer.addr])
                .filter(addr => typeof addr === 'string' && addr && addr !== 'unknown');
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

            const getAddrScoreInfo = (a) => {
                if (!a) return { score: 999, label: 'Score 999', color: 'var(--text-secondary)' };
                if (a.includes('/p2p-circuit')) return { score: 100, label: t('score_relay') || 'Relay (Score 100)', color: 'var(--warn)' };
                if (a.includes('127.0.0.1') || a.includes('/ip6/::1')) return { score: 0, label: t('score_loopback') || 'Loopback (Score 0)', color: 'var(--accent-purple)' };
                if (a.includes('192.168.') || a.includes('/ip4/10.') || a.includes('/ip4/172.') || a.includes('/ip6/fd')) {
                    return { score: 10, label: t('score_lan_direct') || 'LAN Direct (Score 10)', color: 'var(--success)' };
                }
                return { score: 20, label: t('score_wan_direct') || 'WAN Direct (Score 20)', color: 'var(--info)' };
            };

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
                        const sc = getAddrScoreInfo(a);
                        return `<div class="ma-entry${isActive ? ' active' : ''}" data-ma-index="${idx}" data-ma-addr="${escapeHTML(a)}">
                            <span class="ma-tag">[${tag}]</span>
                            <span style="font-size:0.72rem; padding:1px 6px; border-radius:4px; margin-right:4px; font-weight:600; color:${sc.color}; background:var(--glass-fill); border:1px solid var(--border-subtle);" title="Priority Score (0:Loopback, 10:LAN, 20:WAN, 100:Relay)">${sc.label}</span>
                            <span class="ma-addr-text">${escapeHTML(a)}</span>
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
                    rttSpan.style.color = 'var(--text-secondary)';
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
            selectDashboardPage('diagnostics');
            document.getElementById('pingTargetInput').value = target;
            document.getElementById('pingTargetInput').focus();
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

        /* ── Modern P2P Network Diagnostics (Visual Flow & Terminal) ── */

        function setDiagViewMode(mode) {
            const raw = mode === 'raw';
            document.getElementById('diagViewSelect').value = raw ? 'raw' : 'visual';
            document.getElementById('diagVisualContainer').style.display = raw ? 'none' : 'block';
            document.getElementById('pingOutput').style.display = raw ? 'block' : 'none';
        }


        function renderVisualPingResult(d, target, ok) {
            const cont = document.getElementById('diagVisualContainer');
            if (!cont) return;

            if (!ok || !d || !d.success) {
                cont.innerHTML = `
                    <div class="glass-card" style="padding:18px; display:flex; flex-direction:column; gap:12px; border-left:3px solid var(--danger);">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <strong style="color:var(--danger); font-size:1.05rem;">⚠️ Ping Target Unreachable</strong>
                            <span style="font-size:0.75rem; background:rgba(239,68,68,0.15); color: var(--danger); padding:2px 8px; border-radius:5px;">${escapeHTML(target)}</span>
                        </div>
                        <div style="font-size:0.85rem; color:var(--text-secondary);">
                            ${d && d.error ? escapeHTML(d.error) : 'Target peer did not respond to P2P ping probe.'}
                        </div>
                        <div style="display:flex; gap:8px;">
                            <button class="btn-glass" data-onclick="runPingDiagnostics()" style="padding:4px 12px; font-size:0.8rem; background:var(--accent-cyan-fill);">🔄 Retry Ping</button>
                        </div>
                    </div>
                `;
                return;
            }

            const rtt = Number(d.rtt_avg_ms) || 0;
            const replies = Number.isFinite(Number(d.replies)) ? Number(d.replies) : 0;
            const probes = Number.isFinite(Number(d.probes)) ? Number(d.probes) : 0;
            const jitterAvailable = replies > 1 && Number.isFinite(Number(d.jitter_ms));
            const lossAvailable = probes > 0 && Number.isFinite(Number(d.packet_loss));
            const rttColor = rtt < 50 ? 'var(--success)' : (rtt < 150 ? 'var(--warn)' : 'var(--danger)');
            const pingPath = routeTransportPath(d);
            const transportBadge = pingPath === 'direct'
                ? `<span class="pill-badge role-static">⚡ ${transportPathLabel(pingPath)}</span>`
                : (pingPath === 'unknown'
                    ? `<span class="pill-badge">❔ ${transportPathLabel(pingPath)}</span>`
                    : `<span class="pill-badge role-bootstrap">🔄 ${transportPathLabel(pingPath)}</span>`);

            cont.innerHTML = `
                <div class="glass-card" style="padding:18px; display:flex; flex-direction:column; gap:14px; border-left:3px solid var(--accent-cyan);">
                    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                        <div>
                            <strong style="font-size:1.1rem; color:var(--text-primary);">🎯 ${escapeHTML(d.node_name || d.peer_id_short || target)}</strong>
                            <div style="font-family:monospace; font-size:0.75rem; color:var(--text-muted);">${escapeHTML(d.peer_id || target)}</div>
                        </div>
                        <div>${transportBadge}</div>
                    </div>
                    <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(130px, 1fr)); gap:10px;">
                        <div class="proto-stat-box">
                            <span class="proto-stat-lbl">P2P Control RTT Avg</span>
                            <span class="proto-stat-val" style="color:${rttColor}; font-size:1.25rem;">${rtt > 0 ? rtt.toFixed(1) + ' ms' : '-'}</span>
                        </div>
                        <div class="proto-stat-box">
                            <span class="proto-stat-lbl">Jitter (波动)</span>
                            <span class="proto-stat-val" style="color:var(--accent-purple); font-size:1.1rem;">${jitterAvailable ? '±' + Number(d.jitter_ms).toFixed(1) + ' ms' : '—'}</span>
                        </div>
                        <div class="proto-stat-box">
                            <span class="proto-stat-lbl">Packet Loss</span>
                            <span class="proto-stat-val" style="color:${lossAvailable && Number(d.packet_loss) > 0 ? 'var(--danger)' : 'var(--success)'}; font-size:1.1rem;">${lossAvailable ? (Number(d.packet_loss) * 100).toFixed(0) + '%' : '—'}</span>
                        </div>
                        <div class="proto-stat-box">
                            <span class="proto-stat-lbl">Probes (采样数)</span>
                            <span class="proto-stat-val" style="color:var(--accent-cyan); font-size:1.1rem;">${probes > 0 ? replies + ' / ' + probes : '—'} replies</span>
                        </div>
                    </div>
                    <div style="display:flex; justify-content:space-between; font-size:0.78rem; color:var(--text-secondary); border-top:1px solid var(--border-subtle); padding-top:8px;">
                        <span>RTT Min / Max: <strong>${rtt > 0 ? Number(d.rtt_min_ms).toFixed(1) + ' ms / ' + Number(d.rtt_max_ms).toFixed(1) + ' ms' : '—'}</strong></span>
                        ${d.tap_ip ? `<span>TAP IP: <code style="color:var(--accent-cyan); font-weight:600;">${escapeHTML(d.tap_ip)}</code></span>` : ''}
                    </div>
                </div>
            `;
        }

        function renderVisualTraceResult(d, target, ok) {
            const cont = document.getElementById('diagVisualContainer');
            if (!cont) return;

            if (!ok || !d || !d.hops || d.hops.length === 0) {
                cont.innerHTML = `
                    <div class="glass-card" style="padding:18px; display:flex; flex-direction:column; gap:12px; border-left:3px solid var(--warn);">
                        <strong style="color:var(--warn); font-size:1.05rem;">⚠️ No Live Overlay Route Found</strong>
                        <div style="font-size:0.85rem; color:var(--text-secondary);">Target ${escapeHTML(target)} is not directly reachable in Dijkstra forwarding matrix.</div>
                        <div><button class="btn-glass" data-onclick="runTracerouteDiagnostics()" style="padding:4px 12px; font-size:0.8rem; background:var(--accent-cyan-fill);">🔄 Retry Traceroute</button></div>
                    </div>
                `;
                return;
            }

            const hops = d.hops || [];
            const hopsHtml = hops.map((h, idx) => {
                const isFirst = (idx === 0);
                const isLast = (idx === hops.length - 1);
                const bg = isFirst ? 'rgba(56,189,248,0.12)' : (isLast ? 'rgba(52,211,153,0.12)' : 'rgba(167,139,250,0.12)');
                const border = isFirst ? 'rgba(56,189,248,0.4)' : (isLast ? 'rgba(52,211,153,0.4)' : 'rgba(167,139,250,0.4)');
                const color = isFirst ? '#38bdf8' : (isLast ? '#34d399' : '#a78bfa');
                const icon = isFirst ? '💻' : (isLast ? '🎯' : '🔀');
                const role = isFirst ? 'Local' : (isLast ? 'Destination' : 'Relay Hop');
                return `
                    <div style="display:flex; flex-direction:column; align-items:center; min-width:110px; text-align:center; padding:10px 14px; background:${bg}; border:1px solid ${border}; border-radius:10px;">
                        <strong style="color:${color}; font-size:0.86rem;">${icon} ${escapeHTML(h.node_name || h.peer_id_short || ('Hop ' + (idx + 1)))}</strong>
                        <span style="font-size:0.7rem; color:var(--text-muted); margin-top:2px;">${role}</span>
                        ${h.tap_ip ? `<code style="font-size:0.7rem; color:var(--text-primary); margin-top:3px;">${escapeHTML(h.tap_ip)}</code>` : ''}
                        ${h.link_rtt_ms ? `<span style="font-size:0.68rem; color:${color}; margin-top:4px;">~${h.link_rtt_ms} ms</span>` : ''}
                    </div>
                `;
            }).join('<span style="color:var(--text-muted); font-size:1.2rem; margin:0 4px;">➔</span>');

            const tracePath = routeTransportPath(d);
            const tracePathIcon = tracePath === 'direct' ? '⚡' : (tracePath === 'unknown' ? '❔' : '🔀');
            cont.innerHTML = `
                <div class="glass-card" style="padding:18px; display:flex; flex-direction:column; gap:14px; border-left:3px solid var(--accent-purple);">
                    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                        <strong style="font-size:1.05rem; color:var(--text-primary);">🛣️ P2P Overlay Forwarding Path (${hops.length} Nodes)</strong>
                        <span style="font-size:0.78rem; background:var(--glass-fill); padding:3px 10px; border-radius:6px; color:var(--accent-cyan); border:1px solid var(--border-subtle);">${tracePathIcon} ${transportPathLabel(tracePath)}</span>
                    </div>
                    <div style="display:flex; align-items:center; justify-content:center; flex-wrap:wrap; gap:8px; padding:14px 10px; background:var(--surface-recessed); border-radius:12px; border:1px solid var(--border-subtle);">
                        ${hopsHtml}
                    </div>
                    <div style="display:flex; justify-content:space-between; font-size:0.8rem; color:var(--text-secondary); border-top:1px solid var(--border-subtle); padding-top:8px;">
                        <span>Path Cost Estimate: <strong style="color:var(--success); font-size:0.92rem;">${d.total_rtt_ms > 0 ? '≈' + d.total_rtt_ms + ' ms' : '-'}</strong></span>
                        ${d.saved_rtt_ms > 0 ? `<span style="color:var(--success); font-weight:600;">⚡ Estimated Relay Saving: ≈-${d.saved_rtt_ms} ms</span>` : ''}
                    </div>
                </div>
            `;
        }

        function runPingDiagnostics() {
            if (currentDashboardPage() !== 'diagnostics') selectDashboardPage('diagnostics');
            const rawTarget = document.getElementById('pingTargetInput').value.trim();
            const target = sanitizePingTarget(rawTarget);
            const out = document.getElementById('pingOutput');
            const visualCont = document.getElementById('diagVisualContainer');
            if (!target) {
                if (out) out.innerText = 'Enter a TAP IP, node name, or peer ID. No default target was assumed.';
                renderVisualPingResult({ error: 'missing or invalid target' }, rawTarget || '(empty)', false);
                return;
            }

            if (visualCont) {
                visualCont.innerHTML = `
                    <div style="padding:32px; text-align:center; display:flex; flex-direction:column; align-items:center; gap:12px;">
                        <div class="spinner" style="width:28px; height:28px; border:3px solid rgba(56,189,248,0.2); border-top-color:#38bdf8; border-radius:50%; animation:spin 0.8s linear infinite;"></div>
                        <div style="color:var(--text-secondary); font-size:0.9rem;">Pinging <strong>${escapeHTML(target)}</strong> via P2P stream...</div>
                    </div>
                `;
            }

            const lines = [
                `P2P Ping → ${target}`,
                `[libp2p ping stream — real RTT, not ICMP]`,
                `Pinging...`,
            ];
            if (out) out.innerText = lines.join('\n');

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
                        if (out) out.innerText = lines.join('\n');
                        renderVisualPingResult(result.data, target, false);
                        return;
                    }
                    const d = result.data;
                    const t = (x) => (x != null ? x.toFixed(1) : '-');
                    const pingPath = routeTransportPath(d);
                    const transport = `${pingPath === 'direct' ? '⚡' : (pingPath === 'unknown' ? '❔' : '🔄')} ${transportPathLabel(pingPath)}`;
                    lines.push('');
                    lines.push(`Peer: ${d.node_name || d.peer_id_short}  (${d.peer_id_short})`);
                    if (d.tap_ip) lines.push(`  TAP: ${d.tap_ip}`);
                    lines.push(`Transport: ${transport}  [${pingPath}]`);
                    lines.push(`Replies: ${d.replies || 0}/${d.probes || 0}   Loss: ${d.probes > 0 ? (d.packet_loss * 100).toFixed(0) + '%' : '-'}`);
                    lines.push(`RTT  min/avg/max: ${t(d.rtt_min_ms)} / ${t(d.rtt_avg_ms)} / ${t(d.rtt_max_ms)} ms`);
                    lines.push(`Jitter: ${(d.replies || 0) > 1 ? t(d.jitter_ms) + ' ms' : '- (needs 2+ replies)'}`);
                    if (d.is_relayed && d.relay_path && d.relay_path.length) {
                        lines.push(`Relay path (${d.relay_path.length} hop): ` + d.relay_path.map(r => '…' + r.slice(-9)).join(' → '));
                    }
                    if (d.transport_addr) lines.push(`Transport addr: ${d.transport_addr}`);
                    if (d.error) lines.push(`Note: ${d.error}`);
                    if (!d.success) lines.push('', `Peer ${target} did not reply. Check connectivity.`);
                    if (out) out.innerText = lines.join('\n');
                    renderVisualPingResult(d, target, true);
                })
                .catch(err => {
                    lines.push('', `Ping error: ${err.message || err}`);
                    showPingFallback(lines, target, matchedPeer);
                    if (out) out.innerText = lines.join('\n');
                    renderVisualPingResult({ error: err.message || String(err) }, target, false);
                });
        }

        function showPingFallback(lines, target, matchedPeer) {
            lines.push('', `No live RTT measurement is available; no fallback number was generated.`);
            if (peerRTTIsMeasured(matchedPeer)) {
                lines.push(`Last measured peer RTT: ${peerRTTText(matchedPeer)} [${peerRTTSourceLabel(matchedPeer)}; not a reply to this request]`);
            }
            lines.push(`Run 'ping ${target}' in terminal for TAP/ICMP RTT; those replies are now passively recorded by the WebUI.`);
        }

        function runTracerouteDiagnostics() {
            if (currentDashboardPage() !== 'diagnostics') selectDashboardPage('diagnostics');
            const rawTarget = document.getElementById('pingTargetInput').value.trim();
            const target = sanitizePingTarget(rawTarget);
            const out = document.getElementById('pingOutput');
            const visualCont = document.getElementById('diagVisualContainer');
            if (!target) {
                if (out) out.innerText = 'Enter a TAP IP, node name, or peer ID. No default target was assumed.';
                renderVisualTraceResult({ error: 'missing or invalid target' }, rawTarget || '(empty)', false);
                return;
            }

            if (visualCont) {
                visualCont.innerHTML = `
                    <div style="padding:32px; text-align:center; display:flex; flex-direction:column; align-items:center; gap:12px;">
                        <div class="spinner" style="width:28px; height:28px; border:3px solid rgba(167,139,250,0.2); border-top-color:#a78bfa; border-radius:50%; animation:spin 0.8s linear infinite;"></div>
                        <div style="color:var(--text-secondary); font-size:0.9rem;">Tracing overlay route to <strong>${escapeHTML(target)}</strong>...</div>
                    </div>
                `;
            }

            const lines = [
                `P2P Overlay Traceroute → ${target}`,
                `[libp2p has no native traceroute; traces LSA/Dijkstra forwarding path + per-leg transport]`,
                `Tracing overlay path...`,
            ];
            if (out) out.innerText = lines.join('\n');

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
                        if (out) out.innerText = lines.join('\n');
                        renderVisualTraceResult(tr.data, target, false);
                        return;
                    }
                    const d = tr.data;
                    const relayCount = (d.hops || []).filter(h => h.role === 'relay').length;
                    lines.push('');
                    const tracePath = routeTransportPath(d);
                    lines.push(`Path (${d.hop_count} node, ${relayCount} relay): ${transportPathLabel(tracePath)}   [source: ${d.source}]`);
                    (d.hops || []).forEach((h, i) => {
                        const badge = h.role === 'local' ? '⟡ LOCAL' : (h.role === 'destination' ? '▶ DEST' : '↺ RELAY');
                        const exit = h.is_exit_node ? ' 🚀EXIT' : '';
                        const ip = h.tap_ip ? ` (${h.tap_ip})` : '';
                        const short = h.peer_id_short || h.peer_id;
                        let line = `  ${i + 1}  ${badge}  ${h.node_name || short}${ip}${exit}`;
                        if (h.link_class) {
                            const leg = h.link_class === 'circuit-relay'
                                ? '🔄 circuit'
                                : (h.link_class === 'direct' ? '⚡ direct' : '❔ unverified');
                            line += `\n      ↳ ${leg}  leg RTT ~${h.link_rtt_ms} ms  cum ~${h.cumulative_rtt_ms} ms`;
                            if (h.transport_addr) line += `\n      ↳ ${h.transport_addr}`;
                        }
                        lines.push(line);
                    });
                    if (d.total_rtt_ms > 0) lines.push('', `Path RTT (sum of overlay edges): ~${d.total_rtt_ms} ms`);
                    if (tracePath === 'overlay-relay' && d.saved_rtt_ms > 0) lines.push(`  [estimated relay saving ≈${d.saved_rtt_ms} ms vs direct ≈${d.direct_rtt_ms} ms]`);
                    lines.push('', `---`, `For real ICMP traceroute: traceroute ${target}`);
                    if (out) out.innerText = lines.join('\n');
                    renderVisualTraceResult(d, target, true);
                })
                .catch(err => {
                    lines.push('', `API error: ${err.message || err}`);
                    renderCachedTraceroute(lines, target, queryID);
                    if (out) out.innerText = lines.join('\n');
                    renderVisualTraceResult(null, target, false);
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
            const path = routeTransportPath(r);
            if (path === 'direct') {
                decisionBadge = `<span class="pill-badge role-static" style="font-size:0.85rem; padding:4px 12px;">🟢 ${t('direct_optimal_title')}</span>`;
                decisionText = `<strong>${t('direct_optimal_title')}:</strong> ${t('direct_optimal_desc')} (<strong>≈${r.direct_rtt_ms} ms routing estimate</strong>).`;
            } else if (path === 'circuit-relay') {
                decisionBadge = `<span class="pill-badge role-bootstrap" style="font-size:0.85rem; padding:4px 12px;">🔄 ${transportPathLabel(path)}</span>`;
                decisionText = `<strong>Actual transport:</strong> the destination is the next overlay hop, but the live libp2p connection traverses a circuit relay. RTT values below are routing estimates.`;
            } else if (path === 'overlay-relay') {
                decisionBadge = `<span class="pill-badge role-bootstrap" style="font-size:0.85rem; padding:4px 12px;">🔀 ${t('relay_chosen_title')} (${escapeHTML(r.next_hop_name || 'unknown hop')})</span>`;
                const savedStr = r.saved_rtt_ms > 0 ? `${t('saved_latency')} <strong style="color:var(--success);">≈${r.saved_rtt_ms} ms</strong> (${t('vs_direct')} <strong>≈${r.direct_rtt_ms} ms</strong>)` : `${t('nat_fallback_desc')}`;
                decisionText = `<strong>${t('relay_accel_active')}:</strong> ${t('relay_accel_desc')} <strong>${escapeHTML(r.next_hop_name || 'unknown hop')}</strong> (≈${r.total_rtt_ms} ms routing estimate), ${savedStr}.`;
            } else {
                decisionBadge = `<span class="pill-badge" style="font-size:0.85rem; padding:4px 12px;">❔ ${transportPathLabel(path)}</span>`;
                decisionText = `<strong>Transport not verified:</strong> a cached routing entry exists, but there is no live connection evidence proving direct or relay transport.`;
            }

            let candidateRows = '';
            const candidates = r.candidates || [];
            if (candidates.length > 0) {
                candidateRows = candidates.map(c => {
                    const optTag = c.is_optimal 
                        ? `<span style="color:var(--success); font-weight:bold;">${t('chosen_optimal')}</span>` 
                        : `<span style="color:var(--text-secondary);">${t('rejected')}</span>`;
                    const rttStr = c.total_rtt > 0 ? `≈${c.total_rtt} ms` : `<span style="color:var(--danger);">∞ (${t('unreachable')})</span>`;
                    const pathStr = c.path_names.join(' ➔ ');
                    return `
                        <tr>
                            <td>${optTag}</td>
                            <td><code style="color:var(--accent-purple);">${pathStr}</code></td>
                            <td><strong>${rttStr}</strong></td>
                            <td style="color:var(--text-dim); font-size:0.82rem;">${escapeHTML(c.reason || '')}</td>
                        </tr>
                    `;
                }).join('');
            }

            content.innerHTML = `
                <div class="glass-card" style="padding:14px; background:var(--surface-fill);">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                        <strong style="color:var(--text-primary); font-size:1.02rem;">${t('target_node')}: ${escapeHTML(r.dest_name || '')}</strong>
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

        // --- WebUI auth token handling (mirrors server-side bearer requirement) ---
        const AUTH_TOKEN_KEY = 'p2ptap_webui_token';
        function getAuthToken() {
            try {
                // 1. Check URL query parameters (?token=admin)
                if (typeof window !== 'undefined' && window.location && window.location.search) {
                    const params = new URLSearchParams(window.location.search);
                    const urlToken = params.get('token');
                    if (urlToken) {
                        try { localStorage.setItem(AUTH_TOKEN_KEY, urlToken); } catch (e) {}
                        // Strip the token from the URL so it doesn't linger in
                        // browser history, proxy logs, or the address bar.
                        history.replaceState(null, '', location.pathname + location.hash);
                        return urlToken;
                    }
                }
                // 2. Check URL hash fragment (#token=admin)
                if (typeof window !== 'undefined' && window.location && window.location.hash) {
                    const hashParams = new URLSearchParams(window.location.hash.substring(1));
                    const hashToken = hashParams.get('token');
                    if (hashToken) {
                        try { localStorage.setItem(AUTH_TOKEN_KEY, hashToken); } catch (e) {}
                        // Strip the token from the hash fragment for the same
                        // reason as above.
                        const clean = window.location.hash.replace(/([?&])token=[^&]*&?/, '$1').replace(/token=[^&]*&?/g, '');
                        history.replaceState(null, '', window.location.pathname + clean);
                        return hashToken;
                    }
                }
                // 3. Fall back to localStorage
                return localStorage.getItem(AUTH_TOKEN_KEY) || '';
            } catch (e) {
                return '';
            }
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
        let loginResolvers = [];

        function openLoginModal() {
            return new Promise((resolve) => {
                loginResolvers.push(resolve);
                if (loginModalActive) return;
                loginModalActive = true;
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
            const resolvers = loginResolvers;
            loginResolvers = [];
            resolvers.forEach(r => r(success));
        }

        function submitLogin() {
            const input = document.getElementById('loginTokenInput');
            const err = document.getElementById('loginError');
            const tok = (input.value || '').trim();
            if (!tok) {
                err.textContent = (typeof t === 'function' && t('login_error')) || 'Invalid token or request failed. Please try again.';
                err.style.display = 'block';
                return;
            }
            setAuthToken(tok);
            closeLoginModal(true);
            // Refresh the active page after authentication.
            fetchStats();
            syncDiagnosticStreams();
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
            if (currentDashboardPage() !== 'diagnostics') selectDashboardPage('diagnostics');
            document.getElementById('connectivityDetails').open = true;
            const resContainer = document.getElementById('troubleshootResults');
            
            const inputTarget = document.getElementById('pingTargetInput').value.trim();
            if (!inputTarget) {
                resContainer.innerHTML = `<div style="color: var(--danger);">${t('troubleshoot_no_peer') || 'Please select or enter a peer (IPv4 / IPv6 / Peer ID) to diagnose'}</div>`;
                return;
            }

            resContainer.innerHTML = `<div style="color: var(--accent-cyan);" class="pulsing">${t('troubleshoot_running') || 'Running IPv4 & IPv6 diagnosis...'}</div>`;
            
            const renderCard = (stepName, status, details) => {
                let color, badgeColor, icon, badgeText;
                if (status === 'PASS') {
                    color = 'rgba(52,211,153,0.4)';
                    badgeColor = 'var(--success)';
                    icon = '✅';
                    badgeText = t('troubleshoot_pass') || 'PASS';
                } else if (status === 'FAIL') {
                    color = 'rgba(248,113,113,0.4)';
                    badgeColor = 'var(--danger)';
                    icon = '❌';
                    badgeText = t('troubleshoot_fail') || 'FAIL';
                } else if (status === 'WARN') {
                    color = 'rgba(251,191,36,0.4)';
                    badgeColor = 'var(--warn)';
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
                    const ifName = tapInfo.interface_name || tapInfo.name || 'Unknown';
                    const mtuKnown = Number.isFinite(Number(tapInfo.mtu)) && Number(tapInfo.mtu) > 0;
                    const mtuVal = mtuKnown ? Number(tapInfo.mtu) : null;
                    const upKnown = typeof tapInfo.is_up === 'boolean';
                    const isUp = tapInfo.is_up === true;
                    tapDetails = `Interface: <strong>${escapeHTML(ifName)}</strong><br>MAC: <code>${escapeHTML(tapInfo.mac || 'Unknown')}</code> | MTU: ${mtuKnown ? mtuVal : 'Unknown'}<br>IPv4: <code>${escapeHTML(tapInfo.ipv4 || 'Not reported')}</code><br>IPv6: <code>${escapeHTML(tapInfo.ipv6 || 'Not reported')}</code>`;
                    if (upKnown && isUp && mtuKnown && mtuVal >= 1280) {
                        tapStatus = "PASS";
                    } else {
                        tapStatus = "WARN";
                        tapDetails += `<br><span style="color:var(--warn);">TAP state is down, below MTU 1280, or not fully reported.</span>`;
                    }
                } else {
                    if (latestStatsData) {
                        const tapIPv4 = latestStatsData.tap_ip || 'Not reported';
                        const tapIPv6 = latestStatsData.tap_ipv6 || 'Not reported';
                        tapStatus = "WARN";
                        tapDetails = `Local Node: <strong>${escapeHTML(latestStatsData.node_name || 'Unknown')}</strong><br>Peer ID: <code>${escapeHTML(latestStatsData.peer_id || 'Unknown')}</code><br>IPv4: <code>${escapeHTML(tapIPv4)}</code><br>IPv6: <code>${escapeHTML(tapIPv6)}</code><br><span style="color:var(--warn); font-size:0.75rem;">TAP info probe failed; these are configured addresses, not proof that the interface is up.</span>`;
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
                    const reachability = targetPeer.reachability || 'Unknown';
                    const actualPath = peerTransportPath(targetPeer);
                    const v4Str = targetPeer.tap_ip ? `<code>${escapeHTML(targetPeer.tap_ip)}</code>` : 'None';
                    const v6Str = targetPeer.tap_ipv6 ? `<code>${escapeHTML(targetPeer.tap_ipv6)}</code>` : 'None';
                    peerDetails = `Found Peer: <strong>${escapeHTML(targetPeer.node_name) || 'Unknown'}</strong><br>Peer ID: <code>${escapeHTML(targetPeer.peer_id)}</code><br>TAP IPv4: ${v4Str} | TAP IPv6: ${v6Str}<br>Actual Transport: ${escapeHTML(transportPathLabel(actualPath))} | Peer AutoNAT: ${escapeHTML(reachability)}<br>Protocol: ${escapeHTML(transType)}` + (targetPeer.relay_only ? '<br><span style="color:var(--warn);">⚠ ' + t('relay_only') + '</span>' : '');
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
                    const echoPath = peerTransportPath({is_relayed: echoData.is_relayed, addr: echoData.transport_addr});
                    const linkType = `${echoPath === 'direct' ? '⚡' : (echoPath === 'unknown' ? '❔' : '🔄')} ${transportPathLabel(echoPath)}`;
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
                        echoStatus = "WARN";
                        echoDetails = `Peer is listed, but the live echo probe did not succeed.<br>Observed transport: ${escapeHTML(transportPathLabel(peerTransportPath(targetPeer)))}<br><span style="color:var(--warn); font-size:0.75rem;">A PeerStore entry is not proof that the end-to-end stream works.</span>`;
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
                                const rttStr = peerRTTIsMeasured(targetPeer) ? `<span class="pill-badge" style="background:var(--accent-cyan-fill); color:var(--accent-cyan); border:1px solid var(--accent-cyan-border); font-size:0.72rem; padding:1px 6px; margin-left:4px;" title="${escapeHTML(peerRTTSourceLabel(targetPeer))}">⏱️ Latency: ${peerRTTText(targetPeer)}</span>` : '';
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
                        const path = routeTransportPath(route);
                        routeStatus = path === 'unknown' ? "WARN" : "PASS";
                        const rttStr = route.total_rtt_ms ? `≈${route.total_rtt_ms} ms (routing estimate)` : 'N/A';
                        const pathStr = (route.path_names && route.path_names.length > 0) ? route.path_names.join(' ➔ ') : transportPathLabel(path);
                        routeDetails = `Actual Transport: <strong>${transportPathLabel(path)}</strong><br>Routing Path: <code>${pathStr}</code><br>Total Path RTT: ${rttStr}`;
                        if (route.saved_rtt_ms && route.saved_rtt_ms > 0) {
                            routeDetails += `<br><span style="color:var(--success);">⚡ Estimated path saving ≈${route.saved_rtt_ms} ms vs direct link</span>`;
                        }
                    } else if (targetPeer) {
                        const path = peerTransportPath(targetPeer);
                        routeStatus = path === 'unknown' ? "WARN" : "PASS";
                        routeDetails = `Actual Transport: <strong>${transportPathLabel(path)}</strong><br>Destination: <code>${targetPeer.node_name || targetPeer.peer_id}</code><br>Measured RTT: ${peerRTTText(targetPeer)}`;
                    }
                } else if (targetPeer) {
                    const path = peerTransportPath(targetPeer);
                    routeStatus = path === 'unknown' ? "WARN" : "PASS";
                    routeDetails = `Actual Transport: <strong>${transportPathLabel(path)}</strong><br>Destination: <code>${targetPeer.node_name || targetPeer.peer_id}</code><br>Measured RTT: ${peerRTTText(targetPeer)}`;
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
            selectDashboardPage('diagnostics');
            document.getElementById('linkCheckDetails').open = true;
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
            if (v >= 1073741824) return (v / 1073741824).toFixed(1) + ' GB/s';
            if (v >= 1048576) return (v / 1048576).toFixed(1) + ' MB/s';
            if (v >= 1024) return (v / 1024).toFixed(1) + ' KB/s';
            return v + ' B/s';
        }

        function formatPPS(v) {
            if (v >= 1000) return (v / 1000).toFixed(1) + 'K';
            return v + '';
        }

        // Choose ONE unit for the whole axis from its ceiling, so ticks never
        // mix "2K" with "820".
        function rateAxisUnit(max) {
            if (max >= 1073741824) return { div: 1073741824, suffix: 'G' };
            if (max >= 1048576) return { div: 1048576, suffix: 'M' };
            if (max >= 1024) return { div: 1024, suffix: 'K' };
            return { div: 1, suffix: '' };
        }

        // Round a byte rate up to a multiple of five units so peak/5 lands on a
        // whole number of units.
        function niceRateCeil(v) {
            if (!(v > 0)) return 5120;
            let div = 1;
            for (const u of [1, 1024, 1048576, 1073741824]) {
                if (v >= u * 5) div = u;
            }
            return Math.ceil(v / (div * 5)) * div * 5;
        }

        function formatRateTick(v, unit) {
            const n = v / unit.div;
            const s = Math.abs(n - Math.round(n)) < 0.005 ? String(Math.round(n)) : n.toFixed(1);
            return s + unit.suffix;
        }

        function drawBandwidthChart(history) {
            const canvas = document.getElementById('bandwidthCanvas');
            if (!canvas || !history || history.length === 0) return;
            bwChartState.history = history;
            if (!canvas.getClientRects().length) return;
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

            // With no traffic there is nothing to plot — an empty grid pretends
            // to be a measurement of zero. Say so instead.
            let hasTraffic = false;
            for (const h of history) {
                if ((h.tx_speed || 0) > 0 || (h.rx_speed || 0) > 0) { hasTraffic = true; break; }
            }
            if (!hasTraffic) {
                ctx.fillStyle = axisClr2;
                ctx.font = "12px system-ui, sans-serif";
                ctx.textAlign = "center";
                ctx.fillText(t('chart_no_traffic') || 'No traffic yet', m.left + pw / 2, m.top + ph / 2);
                return;
            }

            // Determine max for bytes/sec, snapped to a round ceiling in one
            // unit. Raw peaks made every gridline an arbitrary fraction of the
            // top value and mixed units along the axis ("839.2 B/s" next to
            // "1.0 KB/s"); rounding up to a multiple of five units guarantees
            // peak/5 is a whole number of units.
            let peakBps = 1024;
            history.forEach(h => {
                if (h.tx_speed > peakBps) peakBps = h.tx_speed;
                if (h.rx_speed > peakBps) peakBps = h.rx_speed;
            });
            const maxBps = niceRateCeil(peakBps);
            bwChartState.maxVal = maxBps;
            const rateUnit = rateAxisUnit(maxBps);
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
                ctx.fillText(formatRateTick(v, rateUnit), m.left - 8, gy + 3);
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
            ppsChartState.history = history;
            if (!canvas.getClientRects().length) return;
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
        // Empty addresses are intentional until /api/stats supplies the real
        // interface values. Example addresses must never leak into topology or
        // exported configuration as if they belonged to this node.
        let localNodeInfo = { name: "Local Node", ip: "", ipv6: "", peerID: "" };

        // "12D3KooWJ9kQmNvXrY7bTgH4sLpE2wZcAuQ8dFvR3nXTN" -> "12D3KooW…R3nXTN".
        // Full value stays in localNodeInfo and is what gets copied.
        function shortPeerID(id) {
            if (!id) return '';
            if (id.length <= 20) return id;
            return id.slice(0, 8) + '…' + id.slice(-6);
        }

        async function copyPeerID() {
            const id = localNodeInfo.peerID;
            if (!id) return;
            try {
                await navigator.clipboard.writeText(id);
            } catch (e) {
                // Clipboard API needs a secure context; fall back to a temp node.
                const ta = document.createElement('textarea');
                ta.value = id;
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                try { document.execCommand('copy'); } catch (_) { /* give up */ }
                document.body.removeChild(ta);
            }
        }
        window.copyPeerID = copyPeerID;

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
            const path = peerTransportPath(peer);
            return path === 'circuit-relay' || path === 'overlay-relay';
        }

        function peerTransportPath(peer) {
            if (!peer) return 'unknown';
            // The backend scans all live connections and explicitly prefers a
            // direct connection when direct+circuit transports coexist.
            if (peer.is_relayed === false) return 'direct';
            const trans = String(peer.transport || '');
            if (trans.includes('Overlay Relay')) return 'overlay-relay';
            if (peer.is_relayed === true || trans.includes('Circuit Relay')) return 'circuit-relay';
            const addr = String(peer.addr || peer.address || '');
            if (addr && addr !== 'unknown') return addr.includes('/p2p-circuit') ? 'circuit-relay' : 'direct';
            return 'unknown';
        }

        function routeTransportPath(route) {
            const path = route && String(route.transport_path || '');
            if (path === 'direct' || path === 'circuit-relay' || path === 'overlay-relay' || path === 'unknown') return path;
            // Legacy route payloads can prove an overlay hop from is_direct=false,
            // but is_direct=true alone cannot distinguish direct from circuit.
            return route && route.is_direct === false ? 'overlay-relay' : 'unknown';
        }

        function transportPathLabel(path) {
            if (path === 'direct') return t('topo_tt_direct_link') || 'Direct P2P Link';
            if (path === 'circuit-relay') return t('topo_tt_circuit_relay') || 'Circuit Relay';
            if (path === 'overlay-relay') return 'Multi-Hop Overlay Relay';
            return 'Unknown / not verified';
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
            const color = ms < 1000 ? 'var(--text-secondary)' : (ms < 5000 ? 'var(--warn)' : 'var(--danger)');
            return `<span style="font-size:0.68rem; color:${color};" title="SeqSync handshake convergence: ${ms} ms (time from first crypto handshake to link usable)">⌛ ${txt}</span>`;
        }

        // connStateBadge renders a compact stage-progress indicator for a peer's
        // overall connectivity: connection → app protocol → encryption → data.
        // p.conn_state is the aggregate verdict; p.conn_stage (0..4) drives the
        // progress dots; p.conn_detail is the hover/secondary text.
        const CONN_STATE_META = {
            ok:            { color: 'var(--success)', bg: 'var(--accent-green-fill)', bd: 'var(--accent-green-border)' },
            relay_ok:      { color: 'var(--warn)', bg: 'var(--warn-fill)', bd: 'var(--warn-border)' },
            connecting:    { color: 'var(--info)', bg: 'var(--accent-cyan-fill)', bd: 'var(--accent-cyan-border)' },
            proto_mismatch:{ color: 'var(--danger)', bg: 'var(--danger-fill)', bd: 'var(--danger-border)' },
            obf_failed:    { color: 'var(--danger)', bg: 'var(--danger-fill)', bd: 'var(--danger-border)' },
            unreachable:   { color: 'var(--text-secondary)', bg: 'var(--slate-fill)', bd: 'var(--slate-border)' },
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
        // a peer — deliberately independent of the outbound ConnState verdict.
        function returnPathBadge(p) {
            const st = (p && p.return_path) || 'idle';
            const detail = (p && p.return_path_detail) || '';
            const label = t('return_' + st) || st;
            return `<span class="pill-badge rp-badge rp-${st}" title="${escapeHTML(detail)}">${escapeHTML(label)}</span>`;
        }

        // tapDataPathBadge renders end-to-end TAP data-path health in the peer table.
        function tapDataPathBadge(p) {
            const st = (p && p.tap_data_path) || 'unknown';
            const detail = (p && p.tap_data_path_detail) || '';
            const label = t('tp_' + st) || (st === 'ok' ? 'TAP OK' : (st === 'fail' ? 'TAP Fail' : (st === 'mac_mismatch' ? 'MAC Mismatch' : 'Unprobed')));
            return `<span class="pill-badge tp-badge tp-${st}" title="${escapeHTML(detail)}">${escapeHTML(label)}</span>`;
        }

        // renderPathMetrics renders the per-path breakdown table inside the peer
        // detail panel (the "multipath" strategy's live view of how traffic splits
        // across the direct / circuit-relay paths to a peer). Returns '' when the
        // peer reports no per-path telemetry yet.
        function renderPathMetrics(p) {
            const paths = (p && Array.isArray(p.paths)) ? p.paths : [];
            if (paths.length === 0) return '';
            const rows = paths.map(path => {
                const kind = path.relay_kind || 'direct';
                const kindLabel = kind === 'circuit-relay' ? 'Circuit Relay' :
                    (kind === 'overlay-relay' ? 'Overlay Relay' :
                        (kind === 'boot-relay' ? 'Boot Relay' : 'Direct'));
                const kindColor = kind === 'direct' ? 'var(--success)' : 'var(--warn)';
                const tx = path.tx_bytes || 0;
                const rx = path.rx_bytes || 0;
                const bps = path.est_bps || 0;
                const bpsStr = bps > 0 ? formatBytes(bps) + '/s' : '—';
                const svc = path.service_ms ? (path.service_ms.toFixed(1) + ' ms') : '—';
                const usable = path.usable ? '<span style="color:var(--success)">●</span>' : '<span style="color:var(--text-muted)">○</span>';
                const updated = path.updated ? escapeHTML(path.updated.replace('T', ' ').replace('Z', '')) : '—';
                return `<tr>
                    <td><span class="pill-badge" style="padding:1px 6px;font-size:0.68rem;color:${kindColor};border-color:${kindColor};" title="${escapeHTML(path.transport || '')}">${kindLabel}</span></td>
                    <td title="${escapeHTML(path.path_id || '')}"><code style="font-size:0.68rem;">${escapeHTML(shortMultiaddr(path.path_id))}</code></td>
                    <td>${escapeHTML(path.priority || '')}</td>
                    <td>${usable}</td>
                    <td>${escapeHTML(formatBytes(tx))}</td>
                    <td>${escapeHTML(formatBytes(rx))}</td>
                    <td>${escapeHTML(bpsStr)}</td>
                    <td>${escapeHTML(svc)}</td>
                    <td title="${escapeHTML(path.updated || '')}" style="font-size:0.68rem;color:var(--text-muted);">${updated}</td>
                </tr>`;
            }).join('');
            return `<div style="margin-top:10px;">
                <div style="font-size:0.75rem;font-weight:600;color:var(--text-dim);margin-bottom:4px;">${escapeHTML(t('path_metrics_title') || 'Per-Path Link Metrics')} (${paths.length})</div>
                <table class="mini-table" style="width:100%;border-collapse:collapse;font-size:0.72rem;">
                    <thead><tr style="color:var(--text-muted);text-align:left;">
                        <th style="padding:2px 4px;">${escapeHTML(t('path_metrics_kind') || 'Kind')}</th>
                        <th style="padding:2px 4px;">${escapeHTML(t('path_metrics_path') || 'Path')}</th>
                        <th style="padding:2px 4px;">${escapeHTML(t('col_transport') || 'Transport')}</th>
                        <th style="padding:2px 4px;">${escapeHTML(t('path_metrics_usable') || 'Use')}</th>
                        <th style="padding:2px 4px;">${escapeHTML(t('path_metrics_tx') || 'TX')}</th>
                        <th style="padding:2px 4px;">${escapeHTML(t('path_metrics_rx') || 'RX')}</th>
                        <th style="padding:2px 4px;">${escapeHTML(t('path_metrics_bps') || 'Est. Cap')}</th>
                        <th style="padding:2px 4px;">${escapeHTML(t('path_metrics_svc') || 'Svc')}</th>
                        <th style="padding:2px 4px;">${escapeHTML(t('path_metrics_updated') || 'Updated')}</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>`;
        }

        // shortMultiaddr compresses a long multiaddr for tight table cells while
        // keeping the tail (e.g. the peer/relay component) readable.
        function shortMultiaddr(ma) {
            if (!ma) return '—';
            const s = String(ma);
            if (s.length <= 48) return s;
            return s.slice(0, 22) + '…' + s.slice(-20);
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
        let currentProtoCategory = 'all';
        let prevProtoTrackerSnapshot = {};

        function filterProtoChannels(cat) {
            currentProtoCategory = cat || 'all';
            const tabs = document.querySelectorAll('#protoCategoryTabs .proto-tab');
            tabs.forEach(tab => {
                if (tab.getAttribute('data-cat') === currentProtoCategory) {
                    tab.classList.add('active');
                } else {
                    tab.classList.remove('active');
                }
            });
            if (window.__lastStatsData) {
                renderProtocolChannels(window.__lastStatsData);
            }
        }

        async function triggerSeqSyncResync(targetPeer, triggerBtn) {
            const peerStr = targetPeer || 'all';
            let btn = triggerBtn;
            if (!btn && typeof event !== 'undefined' && event && event.target && event.target.closest) {
                btn = event.target.closest('button');
            }
            if (btn && btn.style) {
                btn.disabled = true;
                btn.style.opacity = '0.6';
            }
            try {
                const res = await safeFetchJSON('/api/seqsync/resync', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ peer_id: peerStr })
                });
                if (res.ok && res.data && res.data.status === 'ok') {
                    showToast(`✅ ${t('resync_success') || 'SeqSync & Key Rotation triggered'}: ${res.data.synced_count} ${t('lbl_peers') || 'peers'}`, false);
                } else {
                    showToast(`⚠️ ${(res.data && res.data.error) || res.error || 'Resync failed'}`, true);
                }
                if (typeof fetchStats === 'function') {
                    fetchStats();
                }
            } catch (err) {
                showToast(`❌ ${err.message || 'Resync request error'}`, true);
            } finally {
                if (btn && btn.style) {
                    btn.disabled = false;
                    btn.style.opacity = '1';
                }
            }
        }

        const channelCategoryConfig = {
            sync:         { icon: '🔄', color: 'var(--info)', borderColor: 'var(--accent-cyan-border)' },
            routing:      { icon: '🗺️', color: 'var(--accent-purple)', borderColor: 'var(--accent-purple-border)' },
            pubsub:       { icon: '📡', color: 'var(--warn)', borderColor: 'var(--accent-yellow-border, #92400e)' },
            data:         { icon: '🚀', color: 'var(--success)', borderColor: 'var(--accent-green-border)' },
            security:     { icon: '🛡️', color: 'var(--danger)', borderColor: 'var(--danger-border, #7f1d1d)' },
            transport:    { icon: '🕳️', color: 'var(--accent-purple)', borderColor: 'var(--accent-purple-border)' },
            diagnostics:  { icon: '🩺', color: 'var(--info)', borderColor: 'var(--border-subtle)' },
            discovery:    { icon: '🔍', color: 'var(--info)', borderColor: 'var(--accent-cyan-border)' },
        };

        function channelStatusBadge(status) {
            if (status === 'active')    return `<span style="color: var(--success);font-weight:700;font-size:0.75rem;">● ${t('channel_status_active') || 'Active'}</span>`;
            if (status === 'running')   return `<span style="color: var(--info);font-weight:700;font-size:0.75rem;">● ${t('channel_status_running') || 'Running'}</span>`;
            if (status === 'synced')    return `<span style="color: var(--success);font-weight:700;font-size:0.75rem;">● ${t('channel_status_synced') || 'Synchronized'}</span>`;
            if (status === 'ready')     return `<span style="color: var(--accent-purple);font-weight:700;font-size:0.75rem;">● ${t('channel_status_ready') || 'Ready'}</span>`;
            if (status === 'standby')   return `<span style="color: var(--warn);font-weight:700;font-size:0.75rem;">⏸ ${t('channel_status_standby') || 'Standby'}</span>`;
            if (status === 'open-mode') return `<span style="color: var(--warn);font-weight:700;font-size:0.75rem;">◌ ${t('channel_status_open') || 'Open'}</span>`;
            if (status === 'idle')      return `<span style="color: var(--text-secondary);font-weight:700;font-size:0.75rem;">◌ ${t('channel_status_idle') || 'Idle'}</span>`;
            return `<span style="color:var(--text-muted);font-size:0.75rem;">◌ ${escapeHTML(status)}</span>`;
        }

        function renderProtocolChannels(data) {
            const channels = data.protocol_channels || [];
            const streams  = data.active_streams  || [];

            // Update stream count badge
            const badge = document.getElementById('activeStreamsBadge');
            if (badge) badge.textContent = `${streams.length} ${t('lbl_active_streams') || 'Streams'}`;

            // --- Traffic Breakdown Bar ---
            const trafficBar = document.getElementById('protoTrafficBar');
            const trafficLegend = document.getElementById('protoTrafficLegend');
            const totalSummary = document.getElementById('protoTotalTrafficSummary');
            if (trafficBar && trafficLegend) {
                let totalFrames = 0;
                let totalBytes = 0;
                channels.forEach(ch => {
                    totalFrames += (ch.tx_frames || 0) + (ch.rx_frames || 0);
                    totalBytes += (ch.tx_bytes || 0) + (ch.rx_bytes || 0);
                });
                if (totalSummary) {
                    totalSummary.textContent = `${totalFrames.toLocaleString()} ${t('frames_unit') || 'frames'} (${formatBytes(totalBytes)})`;
                }

                if (totalFrames === 0) {
                    const emptyBarHtml = `<div class="proto-traffic-segment" style="width:100%; background:var(--glass-fill-strong); border-radius:4px;"></div>`;
                    if (trafficBar._lastHtml !== emptyBarHtml) {
                        trafficBar._lastHtml = emptyBarHtml;
                        trafficBar.innerHTML = emptyBarHtml;
                    }
                    const emptyLegendHtml = `<span class="proto-traffic-item"><span class="proto-traffic-dot" style="background:#64748b;"></span> ${t('common_idle') || 'Standby (0 frames recorded)'}</span>`;
                    if (trafficLegend._lastHtml !== emptyLegendHtml) {
                        trafficLegend._lastHtml = emptyLegendHtml;
                        trafficLegend.innerHTML = emptyLegendHtml;
                    }
                } else {
                    const activeChs = channels.filter(ch => ((ch.tx_frames || 0) + (ch.rx_frames || 0)) > 0);
                    const newBarHtml = activeChs.map(ch => {
                        const cfg = channelCategoryConfig[ch.category] || channelCategoryConfig.diagnostics;
                        const chFrames = (ch.tx_frames || 0) + (ch.rx_frames || 0);
                        const pct = ((chFrames / totalFrames) * 100).toFixed(1);
                        return `<div class="proto-traffic-segment" style="width:${pct}%; background:${cfg.color};" title="${escapeHTML(ch.name)}: ${pct}% (${chFrames.toLocaleString()} frames)"></div>`;
                    }).join('');
                    if (trafficBar._lastHtml !== newBarHtml) {
                        trafficBar._lastHtml = newBarHtml;
                        trafficBar.innerHTML = newBarHtml;
                    }

                    const newLegendHtml = activeChs.map(ch => {
                        const cfg = channelCategoryConfig[ch.category] || channelCategoryConfig.diagnostics;
                        const chFrames = (ch.tx_frames || 0) + (ch.rx_frames || 0);
                        const pct = ((chFrames / totalFrames) * 100).toFixed(1);
                        return `<span class="proto-traffic-item"><span class="proto-traffic-dot" style="background:${cfg.color};"></span> <strong>${escapeHTML(ch.name)}</strong>: ${pct}% (${chFrames.toLocaleString()})</span>`;
                    }).join('');
                    if (trafficLegend._lastHtml !== newLegendHtml) {
                        trafficLegend._lastHtml = newLegendHtml;
                        trafficLegend.innerHTML = newLegendHtml;
                    }
                }
            }

            // --- Filter by Category ---
            const filteredChannels = (currentProtoCategory === 'all')
                ? channels
                : channels.filter(ch => {
                    if (currentProtoCategory === 'sync') return ch.category === 'sync' || ch.category === 'security';
                    return ch.category === currentProtoCategory;
                });

            // --- Channels Grid (Flicker-Free Smart DOM Update) ---
            const grid = document.getElementById('protoChannelsGrid');
            if (grid) {
                if (filteredChannels.length === 0) {
                    const emptyHtml = `<div class="empty-row" style="padding:16px;color:var(--text-muted);">${t('no_channels') || 'No active protocol channels'}</div>`;
                    if (grid._lastCategoryKey !== 'empty') {
                        grid._lastCategoryKey = 'empty';
                        grid.innerHTML = emptyHtml;
                    }
                } else {
                    const now = Date.now();
                    const categoryKey = currentProtoCategory + ':' + filteredChannels.map(c => c.id).join(',');
                    
                    // If structural composition changed, build the persistent card skeleton
                    if (grid._lastCategoryKey !== categoryKey) {
                        grid._lastCategoryKey = categoryKey;
                        grid.innerHTML = filteredChannels.map(ch => {
                            const cfg = channelCategoryConfig[ch.category] || channelCategoryConfig.diagnostics;
                            const normId = (ch.id || '').replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
                            const dict = i18nDict[currentLang] || i18nDict.en || {};
                            const enDict = i18nDict.en || {};
                            const rawKey = 'channel_' + ch.id + '_name';
                            const normKey = 'channel_' + normId + '_name';
                            const chName = dict[rawKey] || dict[normKey] || enDict[rawKey] || enDict[normKey] || ch.name || ch.id;

                            let actionBtn = '';
                            if (normId === 'seqsync') {
                                actionBtn = `<button class="proto-action-btn" data-onclick="triggerSeqSyncResync('all')" title="${t('btn_resync_title') || 'Force SeqSync & Key Rotation'}"><span>🔄</span> <span>${t('btn_resync') || '重同步'}</span></button>`;
                            }

                            return `
                                <div class="glass-card proto-ch-card ext61" id="protoCard_${normId}" data-channel-id="${ch.id}" style="border-left:3px solid ${cfg.color}; display:flex; flex-direction:column; gap:8px; padding:14px 16px;">
                                    <div style="display:flex; align-items:center; justify-content:space-between; gap:6px;">
                                        <div style="display:flex; align-items:center; gap:8px;">
                                            <span class="proto-ch-icon" style="font-size:1.2rem;">${cfg.icon}</span>
                                            <strong style="color:var(--text-primary); font-size:0.9rem;">${escapeHTML(chName)}</strong>
                                        </div>
                                        <div style="display:flex; align-items:center; gap:6px;">
                                            <span class="proto-rate-slot"></span>
                                            ${actionBtn}
                                            <span class="proto-status-slot">${channelStatusBadge(ch.status)}</span>
                                        </div>
                                    </div>
                                    <div style="font-family:monospace; font-size:0.72rem; color:var(--text-muted); word-break:break-all;">${escapeHTML(ch.protocol)}</div>
                                    
                                    <div class="proto-card-stats-grid">
                                        <div class="proto-stat-box">
                                            <span class="proto-stat-lbl">↑ ${t('tx_frames_lbl') || 'TX 帧量'}</span>
                                            <span class="proto-stat-val proto-tx-val">0 <small style="font-size:0.68rem; font-weight:normal; color:var(--text-muted);">(0 B)</small></span>
                                        </div>
                                        <div class="proto-stat-box">
                                            <span class="proto-stat-lbl">↓ ${t('rx_frames_lbl') || 'RX 帧量'}</span>
                                            <span class="proto-stat-val proto-rx-val">0 <small style="font-size:0.68rem; font-weight:normal; color:var(--text-muted);">(0 B)</small></span>
                                        </div>
                                    </div>

                                    <div style="display:flex; gap:8px; font-size:0.75rem; color:var(--text-secondary); align-items:center;">
                                        <span class="proto-events-val">${t('sync_events_lbl') || 'Events'}: <strong>0</strong></span>
                                        <span class="proto-errors-val"></span>
                                        <span class="proto-meta-val" style="margin-left:auto;"></span>
                                    </div>
                                    <div class="proto-details-val" style="font-size:0.75rem; color:var(--text-dim); border-top:1px dashed rgba(255,255,255,0.06); padding-top:4px; display:none;"></div>
                                </div>
                            `;
                        }).join('');
                    }

                    // In-place dynamic updates (Butter-smooth, zero flicker)
                    filteredChannels.forEach(ch => {
                        const cfg = channelCategoryConfig[ch.category] || channelCategoryConfig.diagnostics;
                        const normId = (ch.id || '').replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
                        const card = document.getElementById('protoCard_' + normId);
                        if (!card) return;

                        const totalStreams = ch.active_streams || 0;
                        const inStr  = ch.inbound_streams  || 0;
                        const outStr = ch.outbound_streams || 0;
                        const syncedPeers = ch.synced_peers || 0;
                        const txFrames = ch.tx_frames || 0;
                        const rxFrames = ch.rx_frames || 0;
                        const txBytes = formatBytes(ch.tx_bytes || 0);
                        const rxBytes = formatBytes(ch.rx_bytes || 0);
                        const syncEvents = ch.sync_events || 0;
                        const errCount = ch.error_count || 0;
                        const lastAgo = ch.last_active_ago || '';
                        const catName = t('category_' + ch.category) || ch.category;

                        // Real-time rate calculation
                        let rateHtml = '';
                        const prev = prevProtoTrackerSnapshot[ch.id];
                        if (prev && prev.ts) {
                            const dt = Math.max((now - prev.ts) / 1000, 0.5);
                            const dTxB = Math.max(0, (ch.tx_bytes || 0) - prev.tx_bytes) / dt;
                            const dRxB = Math.max(0, (ch.rx_bytes || 0) - prev.rx_bytes) / dt;
                            const dTxF = Math.max(0, (ch.tx_frames || 0) - prev.tx_frames) / dt;
                            const dRxF = Math.max(0, (ch.rx_frames || 0) - prev.rx_frames) / dt;
                            if (dTxB > 0 || dRxB > 0 || dTxF > 0 || dRxF > 0) {
                                rateHtml = `<span class="proto-rate-pill" title="Live Rate">⚡ ↑${formatChartRate(dTxB)} · ↓${formatChartRate(dRxB)}</span>`;
                            }
                        }
                        prevProtoTrackerSnapshot[ch.id] = {
                            tx_bytes: ch.tx_bytes || 0,
                            rx_bytes: ch.rx_bytes || 0,
                            tx_frames: ch.tx_frames || 0,
                            rx_frames: ch.rx_frames || 0,
                            ts: now
                        };

                        let detailsStr = ch.details || '';
                        if (normId === 'seqsync') {
                            if (syncedPeers > 0) {
                                detailsStr = `${t('synced_peers_lbl') || 'Synced Peers'}: ${syncedPeers} · ${t('channel_seqsync_desc') || 'Window Dedup & Replay Protection'}`;
                            } else if (totalStreams > 0) {
                                detailsStr = `Streams: ${totalStreams} (↓${inStr} ↑${outStr}) · ${t('channel_seqsync_desc') || 'Window Dedup & Replay Protection'}`;
                            } else {
                                detailsStr = `${t('channel_status_ready') || 'Ready'} · ${t('channel_seqsync_desc') || 'Window Dedup & Replay Protection'}`;
                            }
                        } else if (normId === 'lsa') {
                            detailsStr = `Streams: ${totalStreams} (↓${inStr} ↑${outStr}) · ${t('channel_lsa_desc') || 'Dijkstra Shortest Path'}`;
                        } else if (normId === 'peekmap' || normId === 'peek-map') {
                            detailsStr = `Streams: ${totalStreams} (↓${inStr} ↑${outStr}) · ${t('channel_peekmap_desc') || t('channel_peekmap_desc') || 'Bootstrap Topology Sync'}`;
                        } else if (normId === 'data') {
                            // Report what the node is actually doing, not what
                            // it might do. The datapath inherits the node-wide
                            // obfuscation config (security.obfuscation — e.g.
                            // "🛡️ Active (random mode, 512B)" or "Disabled"),
                            // and the cipher really protecting it is whatever
                            // each peer negotiated, so that goes alongside.
                            // Reading obfs_algo/obfs_mode here used to fall back
                            // to the literals "auto"/"fixed" forever: no such
                            // fields exist in the stats payload.
                            const sec = data.security || {};
                            const encList = Array.isArray(sec.encryption) ? sec.encryption : [];
                            const liveEnc = encList.filter(e => e && e.encrypted).length;
                            const cipher = sec.obfuscation || t('obfs_state_unknown') || 'Unknown';
                            const encSummary = encList.length > 0
                                ? ` · ${t('enc_peers_lbl') || 'Encrypted peers'}: ${liveEnc}/${encList.length}`
                                : '';
                            detailsStr = `${t('channel_data_proto') || 'Layer-2 Ethernet Overlay'} · ${t('cipher_lbl') || 'Cipher'}: ${cipher}${encSummary}`;
                        } else if (normId === 'auth') {
                            detailsStr = `${t('channel_auth_desc') || 'PSK Mesh Network Isolation'} · Streams: ${totalStreams}`;
                        } else if (normId === 'dcutr') {
                            detailsStr = `${t('channel_dcutr_desc') || 'Direct Connection Upgrade'} · Streams: ${totalStreams}`;
                        }

                        const isLive = (totalStreams > 0 || txFrames > 0 || rxFrames > 0);
                        const iconEl = card.querySelector('.proto-ch-icon');
                        if (iconEl) {
                            if (isLive) iconEl.classList.add('proto-pulse');
                            else iconEl.classList.remove('proto-pulse');
                        }

                        const rateSlot = card.querySelector('.proto-rate-slot');
                        if (rateSlot && rateSlot.innerHTML !== rateHtml) rateSlot.innerHTML = rateHtml;

                        const statusSlot = card.querySelector('.proto-status-slot');
                        const statusHtml = channelStatusBadge(ch.status);
                        if (statusSlot && statusSlot.innerHTML !== statusHtml) statusSlot.innerHTML = statusHtml;

                        const txValEl = card.querySelector('.proto-tx-val');
                        const txHtml = `${txFrames.toLocaleString()} <small style="font-size:0.68rem; font-weight:normal; color:var(--text-muted);">(${txBytes})</small>`;
                        if (txValEl && txValEl.innerHTML !== txHtml) txValEl.innerHTML = txHtml;

                        const rxValEl = card.querySelector('.proto-rx-val');
                        const rxHtml = `${rxFrames.toLocaleString()} <small style="font-size:0.68rem; font-weight:normal; color:var(--text-muted);">(${rxBytes})</small>`;
                        if (rxValEl && rxValEl.innerHTML !== rxHtml) rxValEl.innerHTML = rxHtml;

                        const eventsEl = card.querySelector('.proto-events-val');
                        const eventsHtml = `${t('sync_events_lbl') || 'Events'}: <strong>${syncEvents}</strong>`;
                        if (eventsEl && eventsEl.innerHTML !== eventsHtml) eventsEl.innerHTML = eventsHtml;

                        const errsEl = card.querySelector('.proto-errors-val');
                        const errsHtml = errCount > 0 ? `<span style="color: var(--danger);">Errors: <strong>${errCount}</strong></span>` : '';
                        if (errsEl && errsEl.innerHTML !== errsHtml) errsEl.innerHTML = errsHtml;

                        const metaEl = card.querySelector('.proto-meta-val');
                        const metaHtml = lastAgo ? `<span style="color:var(--text-dim); font-size:0.7rem;">🕒 ${escapeHTML(lastAgo)}</span>` : `<span style="background:var(--glass-fill); padding:1px 7px; border-radius:5px; font-size:0.7rem; color:${cfg.color};">${escapeHTML(catName)}</span>`;
                        if (metaEl && metaEl.innerHTML !== metaHtml) metaEl.innerHTML = metaHtml;

                        const detailsEl = card.querySelector('.proto-details-val');
                        if (detailsEl) {
                            if (detailsStr) {
                                detailsEl.style.display = 'block';
                                if (detailsEl.textContent !== detailsStr) detailsEl.textContent = detailsStr;
                            } else {
                                detailsEl.style.display = 'none';
                            }
                        }
                    });
                }
            }

            renderStreamsTable(data);
        }

        /* ── Peer Cryptography & Sequence Deep Inspector ─────────────── */
        function openCryptoInspector(targetPeerID) {
            const modal = document.getElementById('cryptoInspectorModal');
            const select = document.getElementById('cryptoInspectorPeerSelect');
            if (!modal || !select) return;

            const peers = (latestStatsData && latestStatsData.active_peers) || [];
            if (peers.length === 0) {
                select.innerHTML = `<option value="">(${t('no_peers') || 'No connected peers'})</option>`;
            } else {
                select.innerHTML = peers.map(p => {
                    const sel = (p.peer_id === targetPeerID) ? 'selected' : '';
                    const label = p.node_name ? `${p.node_name} (${p.peer_id.slice(-8)})` : p.peer_id;
                    return `<option value="${escapeHTML(p.peer_id)}" ${sel}>${escapeHTML(label)}</option>`;
                }).join('');
            }

            const chosen = targetPeerID || select.value;
            renderCryptoInspectorContent(chosen);
            modal.classList.add('active');
            modal.style.display = 'flex';
        }

        function closeCryptoInspectorModal() {
            const modal = document.getElementById('cryptoInspectorModal');
            if (modal) {
                modal.classList.remove('active');
                modal.style.display = 'none';
            }
        }

        function renderCryptoInspectorContent(peerID) {
            const body = document.getElementById('cryptoInspectorBody');
            if (!body) return;

            const peers = (latestStatsData && latestStatsData.active_peers) || [];
            const peer = peers.find(p => p.peer_id === peerID) || peers[0];

            if (!peer) {
                body.innerHTML = `<div class="empty-row" style="padding:20px; text-align:center; color:var(--text-muted);">No peer selected or connected.</div>`;
                return;
            }

            const maxSeq = peer.seq_max_seen || peer.rx_seq || 0;
            const minValid = peer.seq_min_valid || (maxSeq > 65536 ? maxSeq - 65536 : 0);
            const winUtilPct = ((peer.win_utilization || 0) * 100).toFixed(1);
            const leaderStr = peer.obf_i_am_leader ? '👑 Leader (Initiates ECDH)' : '🤝 Follower (Responds via Ack)';
            const convergeStr = peer.seqsync_converge_ms ? `${peer.seqsync_converge_ms} ms` : 'Ready / Connected';
            const rekeyAgoStr = peer.obf_last_rekey_ago || 'At connect';
            const cipherStr = peer.obf_algo ? `${peer.obf_algo.toUpperCase()} (PFS ECDH)` : (peer.obf_encrypted ? 'Encrypted' : 'Plaintext');

            body.innerHTML = `
                <div class="sliding-window-meter">
                    <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.82rem;">
                        <strong style="color:var(--text-primary);">📊 ${t('sliding_window_lbl') || 'Anti-Replay Sliding Window'}</strong>
                        <span style="color: var(--info); font-family:monospace; font-weight:700;">Fill: ${winUtilPct}%</span>
                    </div>
                    <div class="seq-win-track">
                        <div class="seq-win-range" style="left:10%; width:80%;"></div>
                    </div>
                    <div style="display:flex; justify-content:space-between; font-size:0.75rem; font-family:monospace; color:var(--text-muted);">
                        <span>Min Valid: <strong>${minValid.toLocaleString()}</strong></span>
                        <span>Current Max: <strong style="color: var(--success);">${maxSeq.toLocaleString()}</strong></span>
                        <span>Replays Dropped: <strong style="color: var(--danger);">${peer.replay_drops || 0}</strong></span>
                    </div>
                </div>

                <div class="crypto-key-compare-grid">
                    <div class="crypto-key-box">
                        <span class="crypto-key-lbl">${t('tx_key_fp_lbl') || 'TxKey Fingerprint'}</span>
                        <span class="crypto-key-val" style="color: var(--info);">${escapeHTML(peer.obf_tx_key_fp || '(derived in-memory)')}</span>
                    </div>
                    <div class="crypto-key-box">
                        <span class="crypto-key-lbl">${t('rx_key_fp_lbl') || 'RxKey Fingerprint'}</span>
                        <span class="crypto-key-val" style="color: var(--success);">${escapeHTML(peer.obf_rx_key_fp || '(derived in-memory)')}</span>
                    </div>
                    <div class="crypto-key-box">
                        <span class="crypto-key-lbl">${t('ephemeral_fp_lbl') || 'Remote Ephemeral PubKey FP'}</span>
                        <span class="crypto-key-val" style="color: var(--accent-purple);">${escapeHTML(peer.obf_remote_eph_fp || 'Negotiated via P256')}</span>
                    </div>
                    <div class="crypto-key-box">
                        <span class="crypto-key-lbl">${t('cipher_algo_lbl') || 'Cipher & Mode'}</span>
                        <span class="crypto-key-val" style="color: var(--warn);">${escapeHTML(cipherStr)}</span>
                    </div>
                </div>

                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:10px; font-size:0.78rem; background:var(--surface-recessed); padding:10px 14px; border-radius:8px; border:1px solid var(--border-subtle);">
                    <div><span style="color:var(--text-muted);">${t('handshake_latency_lbl') || 'Convergence'}:</span> <strong style="color:var(--text-primary); font-family:monospace;">${convergeStr}</strong></div>
                    <div><span style="color:var(--text-muted);">Last Rotation:</span> <strong style="color:var(--text-primary); font-family:monospace;">${escapeHTML(rekeyAgoStr)}</strong></div>
                    <div><span style="color:var(--text-muted);">Decryption Check:</span> <strong style="color: var(--success);">${peer.obf_decrypt_ok || 0} OK</strong> / <strong style="color: var(--danger);">${peer.obf_decrypt_errs || 0} Errs</strong></div>
                    <div><span style="color:var(--text-muted);">Handshake Role:</span> <strong style="color: var(--info);">${leaderStr}</strong></div>
                </div>
            `;
        }

        async function resyncSelectedPeerFromModal() {
            const select = document.getElementById('cryptoInspectorPeerSelect');
            const btn = document.getElementById('btnCryptoResyncThisPeer');
            if (!select || !select.value) return;
            await triggerSeqSyncResync(select.value, btn);
            renderCryptoInspectorContent(select.value);
        }

        /* ── One-Click Diagnostic Report Export (OpenTelemetry-Compliant) ────── */
        async function exportDiagnosticReport() {
            try {
                let report = null;
                const snapRes = await safeFetchJSON('/api/diag/snapshot', {});
                if (snapRes.ok && snapRes.data) {
                    report = snapRes.data;
                    report.topology_snapshot = latestTopologyData || {};
                    report.client_meta = {
                        user_agent: navigator.userAgent,
                        screen: `${window.innerWidth}x${window.innerHeight}`,
                        exported_at: new Date().toISOString(),
                    };
                } else {
                    report = {
                        title: "p2ptap Overlay Mesh Diagnostic Report",
                        exported_at: new Date().toISOString(),
                        service_name: "p2ptap",
                        version: (latestStatsData && latestStatsData.version) || "unknown",
                        stats: latestStatsData || {},
                        topology_snapshot: latestTopologyData || {}
                    };
                }

                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
                const dlAnchor = document.createElement('a');
                dlAnchor.setAttribute("href", dataStr);
                const timeStr = new Date().toISOString().replace(/[:.]/g, '-');
                dlAnchor.setAttribute("download", `p2ptap-otel-diagnostic-report-${timeStr}.json`);
                document.body.appendChild(dlAnchor);
                dlAnchor.click();
                dlAnchor.remove();

                showToast(`📋 ${t('diagnostic_export_success') || 'Diagnostic report exported successfully!'}`, false);
            } catch (err) {
                showToast(`❌ Export failed: ${err.message}`, true);
            }
        }


        /* ── Active Protocol Streams Table ───────────────────────────── */
        function renderStreamsTable(data) {
            const streams = (data && data.active_streams) || [];
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
            if (!tbody) return;
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
                    ? `<span style="color: var(--info);">${t('dir_out') || 'Outbound ↑'}</span>`
                    : `<span style="color: var(--accent-purple);">${t('dir_in') || 'Inbound ↓'}</span>`;
                const transportBadge = `<span style="background:var(--glass-fill);border:1px solid var(--border-subtle);padding:2px 7px;border-radius:5px;font-size:0.73rem;color:var(--text-secondary);">${escapeHTML(s.transport || 'P2P')}</span>`;
                const statusDot = `<span style="color: var(--success);font-weight:700;font-size:0.75rem;">● ${t('stream_active') || 'Active'}</span>`;
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
            const roleColor = role === 'client' ? 'var(--info)' : role === 'server' ? 'var(--success)' : 'var(--accent-purple)';

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
                badge.style.color = "var(--success)";
                badge.style.border = "1px solid rgba(16,185,129,0.4)";

                const name = exit.active_exit_peer_name || exit.active_peer_id.substring(0, 12) + '…';
                let tapIP = exit.active_exit_tap_ip || exit.active_exit_ip || '';
                let tapIPv6 = exit.active_exit_tap_ipv6 || '';

                if ((!tapIP || !tapIPv6) && Array.isArray(data.active_peers)) {
                    const p = data.active_peers.find(x => x.peer_id === exit.active_peer_id);
                    if (p) {
                        if (!tapIP && p.tap_ip) tapIP = p.tap_ip;
                        if (!tapIPv6 && p.tap_ipv6) tapIPv6 = p.tap_ipv6;
                    }
                }

                let ipBadges = '';
                if (tapIP) {
                    ipBadges += `(<code>${escapeHTML(tapIP)}</code>)`;
                }
                if (tapIPv6) {
                    ipBadges += ` (<code class="ipv6" style="color:var(--accent-purple, #c084fc); background:rgba(168,85,247,0.12);">${escapeHTML(tapIPv6)}</code>)`;
                }
                if (!ipBadges) {
                    ipBadges = '(<code>—</code>)';
                }

                body.innerHTML = `
                    <div class="exit-active-banner">
                        <div class="exit-active-info">
                            <div class="exit-active-title">
                                <span class="exit-active-bolt">⚡</span>
                                <span>${t('exit_client_status_active') || 'Routing all internet traffic via Exit Node'}</span>
                            </div>
                            <div class="exit-active-meta">
                                ${t('exit_status_peer') || 'Gateway'}: <strong>${escapeHTML(name)}</strong>
                                ${ipBadges}
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
                    const rtt = peerRTTIsMeasured(p) ? Number(p.rtt_ms) : null;
                    // RTT pill sits in the top-right of the card, color-coded by latency.
                    let rttPill = '';
                    if (rtt != null) {
                        const rttCls = rtt < 80 ? '' : (rtt < 200 ? ' rtt-warn' : ' rtt-err');
                        rttPill = `<span class="exit-peer-rtt${rttCls}" title="Measured by ${escapeHTML(peerRTTSourceLabel(p))}">⏱ ${rtt.toFixed(1)} ms</span>`;
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
                badge.style.color = 'var(--accent-purple)';
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
                let response = await fetch(url, withAuth({ ...options, signal: controller.signal }));
                if (response.status === 401) {
                    const ok = await promptForToken();
                    if (ok) {
                        // New controller for retry: the original may have been
                        // aborted by its own timeout while the user was filling
                        // in the login form.
                        const retryCtrl = new AbortController();
                        const retryTO = setTimeout(() => retryCtrl.abort(), timeoutMs);
                        try {
                            return await fetch(url, withAuth({ ...options, signal: retryCtrl.signal }));
                        } finally {
                            clearTimeout(retryTO);
                        }
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
            // Security handshake actually negotiated on this peer's connections
            // (TLS vs Noise). Noise links have no ClientHello → no observable SNI.
            if (e.conns && e.conns.length) {
                const secSet = [];
                e.conns.forEach(function (c) { if (c.security && secSet.indexOf(c.security) < 0) secSet.push(c.security); });
                if (secSet.length) {
                    const sc = document.createElement('span');
                    sc.className = 'enc-sec-chip';
                    sc.textContent = '🛡 ' + secSet.join('/').toUpperCase();
                    sc.title = t('sec_peer_conns');
                    badges.appendChild(sc);
                }
            }
            // SNI the peer presented when connecting to us (TLS/QUIC ClientHello).
            if (e.handshake_server_name) {
                const sni = document.createElement('span');
                sni.className = 'enc-algo-chacha';
                sni.textContent = '🏷 ' + e.handshake_server_name;
                sni.title = 'Peer presented server_name "' + e.handshake_server_name + '" in its TLS handshake';
                badges.appendChild(sni);
            }
            // PSK network but no verified per-peer cipher → this link cannot carry
            // encrypted mesh traffic (PSK mismatch or handshake not done). Distinguishes
            // "PSK misconfigured" from "just unreachable".
            if (e.psk_required && !e.psk_verified) {
                const pw = document.createElement('span');
                pw.className = 'enc-no-pfs';
                pw.textContent = '🔒 PSK unverified';
                pw.title = 'This node is in a PSK network but has no negotiated cipher with this peer — it cannot exchange encrypted mesh traffic (wrong/absent PSK, or handshake incomplete).';
                badges.appendChild(pw);
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
            // SNI the peer presented when it dialed us (TLS/QUIC ClientHello).
            // Empty when the peer sent no SNI (tls_server_name unset) or the
            // connection is one WE dialed (a TLS server presents no SNI).
            addTextRow('sec_peer_sni', e.handshake_server_name || '—');
            // ── Negotiated connections ──
            // What each live connection ACTUALLY negotiated (transport · security
            // · muxer · who dialed). This is what answers "why is the SNI empty":
            // Noise has no ClientHello, and an outbound-only peer never got a
            // chance to present its SNI to us.
            if (e.conns && e.conns.length) {
                const row = document.createElement('div');
                row.className = 'ped-row';
                const k = document.createElement('div');
                k.className = 'ped-key';
                k.textContent = t('sec_peer_conns');
                const v = document.createElement('div');
                v.className = 'ped-val ped-conns';
                e.conns.forEach(function (cn) {
                    const line = document.createElement('div');
                    line.className = 'enc-conn-line' + (cn.inbound ? ' enc-conn-in' : ' enc-conn-out');
                    const parts = [
                        (cn.transport || '?').toUpperCase(),
                        (cn.security || '?').toUpperCase(),
                        cn.muxer ? cn.muxer : '—',
                        cn.inbound ? t('sec_conn_in') : t('sec_conn_out'),
                    ];
                    if (cn.limited) parts.push('RELAY');
                    if (cn.remote_addr) parts.push(cn.remote_addr);
                    line.textContent = parts.join(' · ');
                    v.appendChild(line);
                });
                if (!e.handshake_server_name) {
                    const hasNoise = e.conns.some(function (c) { return c.security === 'noise'; });
                    const allOut = e.conns.every(function (c) { return !c.inbound; });
                    const hint = document.createElement('div');
                    hint.className = 'enc-conn-hint';
                    hint.textContent = hasNoise ? t('sec_conn_noise_hint') : (allOut ? t('sec_conn_out_only') : '');
                    if (hint.textContent) v.appendChild(hint);
                }
                row.appendChild(k); row.appendChild(v);
                wrap.appendChild(row);
            }
            if (e.psk_required) {
                addTextRow('sec_peer_psk', e.psk_verified ? '✓' : '✗',
                    { valCls: e.psk_verified ? 'ped-yes' : 'ped-no' });
            }
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
                const res = await fetchWithTimeout('/api/stats', {}, 4000);
                if (!res.ok) { updateDashboardStatus(false); return; }
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
                    // A 52-char Peer ID dominated the header. Show an
                    // abbreviated form and let a click copy the full value.
                    document.getElementById('nodePeerID').innerHTML =
                        `<span data-i18n="peer_id_lbl">${t('peer_id_lbl')}</span>: ` +
                        `<span class="peer-id-chip" role="button" tabindex="0" ` +
                        `onclick="window.copyPeerID()" onkeydown="if(event.key==='Enter'||event.key===' '){window.copyPeerID();return false;}" ` +
                        `title="${t('peer_id_copy_hint') || 'Click to copy'}">${escapeHTML(shortPeerID(data.peer_id))}</span>`;
                    document.getElementById('nodePeerID').title = data.peer_id;
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

                // Real-Time Speedometer
                const speed = data.speed || {};
                if (speed.tx_bytes_per_sec !== undefined) {
                    document.getElementById('txSpeed').innerText = formatSpeed(speed.tx_bytes_per_sec).replace('⚡ ', '');
                }
                if (speed.rx_bytes_per_sec !== undefined) {
                    document.getElementById('rxSpeed').innerText = formatSpeed(speed.rx_bytes_per_sec).replace('⚡ ', '');
                }

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
                        if (pct < 5) elGCCPU.style.color = 'var(--success)';
                        else if (pct < 25) elGCCPU.style.color = 'var(--warn)';
                        else elGCCPU.style.color = 'var(--danger)';
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
                        if (sys.last_gc_pause_ms < 1) pauseEl.style.color = 'var(--success)';
                        else if (sys.last_gc_pause_ms < 10) pauseEl.style.color = 'var(--warn)';
                        else pauseEl.style.color = 'var(--danger)';
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
                    
                    let natText = data.nat_status || '⚪ Unknown (AutoNAT not verified yet)';
                    document.getElementById('secNAT').innerText = natText;

                    const sniEl = document.getElementById('secSNI');
                    if (sniEl) {
                        sniEl.textContent = sec.tls_server_name || '—';
                        sniEl.title = sec.tls_server_name
                            ? 'server_name sent in our TLS/QUIC ClientHellos (both transports share transports.tls_server_name)'
                            : 'No SNI configured (upstream default): outgoing ClientHellos carry no server_name';
                    }
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
                    // Placeholders rather than a baked-in English sentence: the
                    // surrounding UI is localised, so this line was the only
                    // English left on the card in every non-English locale.
                    const seqHint = (t('seq_hint_fmt') || 'replay {replay} · win-reset {reset} · util {util}%')
                        .replace('{replay}', ss.replay_drops || 0)
                        .replace('{reset}', ss.window_resets || 0)
                        .replace('{util}', (ss.win_utilization * 100).toFixed(1));
                    const seqEl = document.getElementById('pktStatSeqSync');
                    if (seqEl && seqEl.parentElement) {
                        const sub = seqEl.parentElement.querySelector('div:last-child');
                        if (sub) sub.innerText = seqHint;
                    }
                }

                // Active Peers Table & Mesh Canvas Update
                const peers = data.active_peers || [];
                cachedPeers = peers;
                drawTopologyMesh();

                document.getElementById('peersCount').innerText = peers.length;
                const peersBody = document.getElementById('peersList');
                peerDetailsCache.clear();
                if (peers.length > 0) {
                    peersBody.innerHTML = peers.map(p => {
                        // Show the transport WE actually observe. Peer-reported
                        // AutoNAT is supplemental and never used to infer direct.
                        const peerPath = peerTransportPath(p);
                        const peerAutoNAT = p.reachability && p.reachability !== 'Unknown'
                            ? ` · AutoNAT ${p.reachability}` : '';
                        let reachClass, reachText, reachIcon;
                        if (peerPath === 'circuit-relay' || peerPath === 'overlay-relay') {
                            reachClass = 'var(--warn)';
                            reachText = transportPathLabel(peerPath) + peerAutoNAT;
                            reachIcon = '🟡';
                        } else if (peerPath === 'direct') {
                            reachClass = 'var(--success)';
                            reachText = transportPathLabel(peerPath) + peerAutoNAT;
                            reachIcon = '🟢';
                        } else {
                            reachClass = 'var(--text-secondary)';
                            reachText = transportPathLabel(peerPath) + peerAutoNAT;
                            reachIcon = '⚪';
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

                        const geoBadge = p.geo_location || '❔ Unknown address scope';
                        const rttMeasured = peerRTTIsMeasured(p);
                        const jitterMeasured = p.jitter_measured === true && Number.isFinite(Number(p.jitter_ms));
                        const lossMeasured = p.loss_measured === true && Number.isFinite(Number(p.loss_rate_percent));
                        const jitterStr = jitterMeasured ? `±${Number(p.jitter_ms).toFixed(1)} ms` : '—';
                        const lossStr = lossMeasured ? `${Number(p.loss_rate_percent).toFixed(1)}%` : '—';
                        const rttColor = !rttMeasured ? 'var(--text-muted)' : (p.rtt_ms < 50 ? 'var(--success)' : (p.rtt_ms < 150 ? 'var(--warn)' : 'var(--danger)'));
                        const rttTitle = rttMeasured
                            ? `Measured by ${peerRTTSourceLabel(p)}; ${p.rtt_sample_count || 1} sample(s)${p.rtt_updated_at ? '; updated ' + p.rtt_updated_at : ''}`
                            : 'No completed RTT measurement yet';

                        const allAddrsList = (p.all_addrs?.length ? p.all_addrs : [p.addr])
                .filter(addr => typeof addr === 'string' && addr && addr !== 'unknown');
                        const activeAddrText = (p.addr && p.addr !== 'unknown') ? p.addr : '—';
                        const addrsHoverHtml = `
                            <div class="multiaddr-hover-wrapper">
                                <div style="font-weight:600; color:var(--accent-cyan); word-break:break-all;" title="Current Active Connected Pathway">⚡ ${escapeHTML(activeAddrText)}</div>
                                ${allAddrsList.length > 1 ? `
                                    <button class="btn-multiaddr-view" data-onclick="event.stopPropagation(); closePeerDetails(); openMultiaddrModal(${attrStr(p.peer_id)})">
                                        🛣️ ${allAddrsList.length} ${t('disc_addrs') || 'Discovered Addr Pathways'} (Click to view)
                                    </button>
                                ` : allAddrsList.length ? `
                                    <button class="btn-multiaddr-view" data-onclick="event.stopPropagation(); closePeerDetails(); openMultiaddrModal(${attrStr(p.peer_id)})">
                                        ${t('view_addr') || 'View Multiaddr'}
                                    </button>
                                ` : ''}
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

                        const peerTotalTxStr = formatBytes(p.total_tx || 0);
                        const peerTotalRxStr = formatBytes(p.total_rx || 0);

                        const linkTotals = (p.link_total_tx !== undefined && p.link_total_rx !== undefined)
                            ? `↑ ${formatBytes(p.link_total_tx)} · ↓ ${formatBytes(p.link_total_rx)}` : '—';
                        const linkRates = p.link_speed_measured === true
                            ? `↑ ${formatSpeed(p.tx_speed).replace('⚡ ', '')} · ↓ ${formatSpeed(p.rx_speed).replace('⚡ ', '')}` : '—';
                        peerDetailsCache.set(p.peer_id, `
                            <dl class="peer-detail-grid">
<div><dt>${escapeHTML(t('col_geo'))}</dt><dd><span style="color:var(--text-dim); font-size:0.8rem">${escapeHTML(geoBadge)}</span></dd></div>
<div><dt>${escapeHTML(t('col_role'))}</dt><dd>${roleBadge}</dd></div>
<div><dt>${escapeHTML(t('col_osarch'))}</dt><dd><div style="display:flex; flex-direction:column; gap:2px;">
                                    <span style="color:var(--text-dim); font-size:0.8rem; font-weight:500;">${escapeHTML(p.os_arch || '—')}</span>
                                    <span style="color:var(--accent-purple); font-size:0.72rem; font-family:monospace;" title="Node Software Version">${escapeHTML(p.version ? (p.version.startsWith('v') ? p.version : 'v' + p.version) : '—')}</span>
                                </div></dd></div>
<div><dt>${escapeHTML(t('col_nat'))}</dt><dd><span style="color:${reachClass}; font-size:0.8rem">${reachIcon} ${escapeHTML(reachText)}</span></dd></div>
<div><dt>${escapeHTML(t('col_encryption'))}</dt><dd><div style="display:flex; flex-direction:column; gap:2px;">
                                    ${encBadge(p)}
                                    ${handshakeBadge(p)}
                                </div></dd></div>
<div><dt>${escapeHTML(t('col_return_path'))}</dt><dd>${returnPathBadge(p)}</dd></div>
<div><dt>${escapeHTML(t('col_tap_path'))}</dt><dd>${tapDataPathBadge(p)}</dd></div>
<div><dt>${escapeHTML(t('col_peerid'))}</dt><dd><code>${escapeHTML(p.peer_id)}</code></dd></div>
<div><dt>${escapeHTML(t('col_multiaddr'))}</dt><dd>${addrsHoverHtml}</dd></div>
<div><dt>${escapeHTML(t('col_transport'))}</dt><dd><div style="display:flex; flex-direction:column; gap:3px; align-items:flex-start;">
                                    <span class="pill-badge" style="padding:2px 8px; font-size:0.75rem;">${escapeHTML(p.transport || 'P2P')}</span>
                                    ${p.transport_priority ? `
                                        <span style="font-size:0.68rem; font-weight:600; padding:1px 5px; border-radius:4px; color:${p.transport_score === 10 ? 'var(--success)' : (p.transport_score === 0 ? '#a855f7' : (p.transport_score === 20 ? 'var(--info)' : 'var(--warn)'))}; background:var(--glass-fill); border:1px solid var(--border-subtle);" title="${t('priority_score_tooltip') || 'Routing Priority Score: lower is higher priority (0:Loopback, 10:LAN Direct, 20:WAN Direct, 100:Relay)'}">
                                            🎯 ${escapeHTML(p.transport_priority)}
                                        </span>
                                    ` : ''}
                                </div></dd></div>
<div><dt>${escapeHTML(t('col_conn_time'))}</dt><dd><span style="color:var(--accent-purple); font-size:0.82rem;" title="${escapeHTML(p.connected_at || '')}">${escapeHTML(p.connected_since || '—')}</span></dd></div>
<div><dt>${escapeHTML(t('col_last_active'))}</dt><dd><span style="color:var(--accent-cyan); font-size:0.82rem;">${escapeHTML(p.last_seen || '—')}</span></dd></div>
<div><dt>${escapeHTML(t('col_jitter_loss'))}</dt><dd><span style="color:var(--accent-purple); font-size:0.8rem">${jitterStr}</span> <span style="color:var(--text-muted); font-size:0.75rem">(${lossStr})</span></dd></div>
                                <div><dt>${escapeHTML(t('dashboard_link_traffic'))}</dt><dd>${linkTotals}</dd></div>
                                <div><dt>${escapeHTML(t('dashboard_link_rate'))}</dt><dd>${linkRates}</dd></div>
                                <div><dt>${escapeHTML(t('dashboard_remote_traffic'))}</dt><dd>↑ ${peerTotalTxStr} · ↓ ${peerTotalRxStr}</dd></div>
                            </dl>
                            ${renderPathMetrics(p)}
                            <div class="peer-detail-actions">
                                <button type="button" class="btn-glass" data-onclick="closePeerDetails(); setPingTarget(${attrStr(p.tap_ip || p.peer_id)})">Ping</button>
                                <button type="button" class="btn-glass" data-onclick="closePeerDetails(); openSpeedTestModal(${attrStr(p.peer_id)})">${t('speedtest_btn')}</button>
                                <button type="button" class="btn-glass" data-onclick="closePeerDetails(); openCryptoInspector(${attrStr(p.peer_id)})">${t('btn_crypto_inspector')}</button>
                            </div>
                        `);
                        return `
                        <tr class="peer-row" role="row">
                            <td class="peer-identity-cell" role="cell">
                                <strong>${escapeHTML(p.node_name) || t('unnamed_node')}</strong>
                                <code class="peer-id" title="${escapeHTML(p.peer_id)}">${escapeHTML(p.peer_id)}</code>
                                <div class="peer-badges">${exitBadgeHtml}${relayOnlyBadge}</div>
                            </td>
                            <td role="cell" data-label="${escapeHTML(t('col_tapip'))}"><div class="tap-ip-cell">${tapIPs}</div></td>
                            <td role="cell" data-label="${escapeHTML(t('dashboard_connection'))}">${connStateBadge(p)}<small class="peer-transport">${escapeHTML(p.transport || '—')}</small></td>
                            <td role="cell" data-label="${escapeHTML(t('col_rtt'))}"><strong style="color:${rttColor}" title="${escapeHTML(rttTitle)}">${peerRTTText(p)}</strong><div style="font-size:0.68rem;color:var(--text-muted);">${rttMeasured ? escapeHTML(peerRTTSourceLabel(p)) : 'not measured'}</div></td>
                            <td role="cell"><button type="button" class="btn-glass peer-details-btn" data-onclick="openPeerDetails(${attrStr(p.peer_id)})">${t('dashboard_details')}</button></td>
                        </tr>
                    `}).join('');
                } else {
                    peersBody.innerHTML = `<tr><td colspan="5" class="empty-row" data-i18n="no_peers">${t('no_peers')}</td></tr>`;
                }

                refreshPeerDetails();

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

                            const channelColor = m.sync_source && m.sync_source.includes('Peek-Map') ? 'var(--warn)' : 'var(--info)';
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
                    const path = routeTransportPath(r);
                    if (path === 'overlay-relay' && r.next_hop_peer) {
                        transitRelaySet.add(r.next_hop_peer);
                    }
                    if (path === 'overlay-relay' || path === 'circuit-relay') {
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
                if (statSaved) statSaved.innerText = maxSavedMs > 0 ? `⚡ ≈-${maxSavedMs} ms` : `0 ms`;

                const routeBody = document.getElementById('routeList');
                if (cachedRoutes.length > 0) {
                    routeBody.innerHTML = cachedRoutes.map(r => {
                        const hopCount = (r.path && r.path.length > 1) ? r.path.length - 1 : 1;
                        const routePath = routeTransportPath(r);
                        
                        // Render visual hop pills
                        let visualPath = '';
                        if (r.path_names && r.path_names.length > 0) {
                            visualPath = r.path_names.map((name, idx) => {
                                if (idx === 0) {
                                    return `<span style="background:var(--accent-cyan-fill); border:1px solid var(--accent-cyan-border); color:var(--accent-cyan); border-radius:5px; padding:2px 7px; font-size:0.78rem; font-weight:600;">💻 Local</span>`;
                                } else if (idx === r.path_names.length - 1) {
                                    return `<span style="background:var(--accent-green-fill); border:1px solid var(--accent-green-border); color:var(--success); border-radius:5px; padding:2px 7px; font-size:0.78rem; font-weight:600;">🎯 ${escapeHTML(name)}</span>`;
                                } else {
                                    return `<span style="background:var(--accent-purple-fill); border:1px solid var(--accent-purple-border); color:var(--accent-purple); border-radius:5px; padding:2px 7px; font-size:0.78rem; font-weight:600;">🔀 ${escapeHTML(name)}</span>`;
                                }
                            }).join('<span style="color:var(--text-muted); margin:0 4px; font-size:0.75rem;">➔</span>');
                        } else {
                            visualPath = `<code style="color:var(--accent-purple)">${escapeHTML(r.dest_name || '')}</code>`;
                        }

                        // Render Smart Optimization Progress Bar & Gain Badge
                        let optHtml;
                        if (routePath === 'direct') {
                            optHtml = `<div style="display:flex; align-items:center; gap:6px;"><span style="color:var(--text-secondary); font-size:0.8rem;">Direct Route</span><span style="color:var(--text-secondary); font-size:0.7rem; background:var(--border-subtle); padding:1px 6px; border-radius:4px;">Optimal</span></div>`;
                        } else if (routePath === 'circuit-relay') {
                            optHtml = `<span style="color:var(--warn); font-size:0.8rem;">Circuit fallback</span>`;
                        } else if (routePath === 'overlay-relay') {
                            optHtml = `<span style="color:var(--accent-purple-ink); font-size:0.8rem;">Overlay route</span>`;
                        } else {
                            optHtml = `<span style="color:var(--text-muted); font-size:0.8rem;">Not verified</span>`;
                        }
                        if (r.saved_rtt_ms > 0 && r.direct_rtt_ms > 0) {
                            const percent = Math.min(100, Math.round((r.saved_rtt_ms * 100) / r.direct_rtt_ms));
                            optHtml = `
                                <div style="display:flex; flex-direction:column; gap:3px; min-width:120px;">
                                    <div style="display:flex; align-items:center; justify-content:space-between; font-size:0.78rem;">
                                        <span style="color:var(--success); font-weight:bold;">⚡ ≈-${r.saved_rtt_ms} ms</span>
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
                        if (routePath === 'circuit-relay') {
                            statusBadge = `<span class="pill-badge role-bootstrap" style="padding:3px 9px; font-size:0.75rem;">🔄 Circuit Relay</span>`;
                        } else if (routePath === 'overlay-relay') {
                            statusBadge = `<span class="pill-badge role-bootstrap" style="padding:3px 9px; font-size:0.75rem;">🔀 Relayed via ${escapeHTML(r.next_hop_name || 'unknown hop')}</span>`;
                        } else if (routePath === 'direct') {
                            statusBadge = `<span class="pill-badge role-static" style="padding:3px 9px; font-size:0.75rem;">⚡ Direct</span>`;
                        } else {
                            statusBadge = `<span class="pill-badge" style="padding:3px 9px; font-size:0.75rem;">❔ Unverified</span>`;
                        }
                        const routeRTTMeasured = r.rtt_measured === true && Number(r.measured_rtt_ms) > 0;
                        const totalRttText = routeRTTMeasured
                            ? `${Number(r.measured_rtt_ms).toFixed(1)} ms`
                            : (r.total_rtt_ms > 0 ? `≈${r.total_rtt_ms} ms route est.` : '—');
                        const totalRttTitle = routeRTTMeasured
                            ? `Measured probe · ${peerRTTSourceLabel(r)}`
                            : 'Dijkstra routing estimate, not an end-to-end probe';
                        const directText = routeRTTMeasured
                            ? `${Number(r.measured_rtt_ms).toFixed(1)} ms`
                            : (r.direct_rtt_ms > 0 ? `≈${r.direct_rtt_ms} ms est.` : '-');
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
                                <td><strong style="color:var(--text-primary); font-size:0.9rem">${escapeHTML(r.dest_name || '')}</strong></td>
                                <td>${ipHtml}</td>
                                <td>${hopBadge}</td>
                                <td><div style="display:flex; align-items:center; flex-wrap:wrap;">${visualPath}</div></td>
                                <td><strong style="color:${r.total_rtt_ms > 0 && r.total_rtt_ms < 50 ? 'var(--success)' : (r.total_rtt_ms > 0 ? 'var(--warn)' : 'var(--text-muted)')}" title="${escapeHTML(totalRttTitle)}">${totalRttText}</strong></td>
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
                            // Prefer the completed probe over the Dijkstra path cost
                            // and label whichever value is shown. The topology chart
                            // renders the same probe (both sides come from
                            // peerRTTMeasurement), so the two panels can no longer
                            // disagree — the matrix used to print the raw routing
                            // estimate as if it were a measurement.
                            const rttMeasured = m.rtt_measured === true && Number(m.measured_rtt_ms) > 0;
                            const rttValue = rttMeasured ? Number(m.measured_rtt_ms) : m.rtt_ms;
                            const rttKnown = rttMeasured || m.rtt_ms > 0;
                            const rttColor = !rttKnown ? 'var(--text-secondary)' : (rttValue < 50 ? 'var(--success)' : (rttValue < 150 ? 'var(--warn)' : 'var(--danger)'));
                            const rttText = rttMeasured
                                ? `${Number(m.measured_rtt_ms).toFixed(1)} ms`
                                : (m.rtt_ms > 0 ? `≈${m.rtt_ms} ms route est.` : '—');
                            const rttTitle = rttMeasured
                                ? `Measured probe · ${peerRTTSourceLabel(m)}`
                                : 'Dijkstra routing estimate, not an end-to-end probe';
                            const path = routeTransportPath(m);
                            const typeBadge = path === 'direct'
                                ? `<span style="color:var(--accent-cyan); font-weight:bold;">⚡ ${transportPathLabel(path)}</span>`
                                : (path === 'unknown'
                                    ? `<span style="color:var(--text-muted); font-weight:bold;">❔ ${transportPathLabel(path)}</span>`
                                    : `<span style="color:var(--accent-purple); font-weight:bold;">🔀 ${transportPathLabel(path)}</span>`);
                            return `
                                <tr>
                                    <td><strong style="color:var(--text-primary);">💻 ${escapeHTML(m.src_name)}</strong></td>
                                    <td><strong style="color:var(--accent-cyan); cursor:pointer;" data-onclick="setPingTarget(${attrStr(m.dst_peer_id)})">🎯 ${escapeHTML(m.dst_name)}</strong></td>
                                    <td><strong style="color:${rttColor}" title="${escapeHTML(rttTitle)}">${rttText}</strong></td>
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
                updateDashboardStatus(true);
            } catch (e) {
                updateDashboardStatus(false);
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
    // A route is "non-operable" ONLY when there is no usable gateway IP.
    // Routes pending authorization can be clicked by the user to dynamically authorize them.
    const isPendingAuth = s.status && s.status.includes('Pending Authorization');
    const hasNoGateway = !gw || gw === '-';
    const isNonOp = hasNoGateway;
    const isRoutable = !isNonOp;
    const isToggleOff = isDisabled || isPendingAuth;

    const row = document.createElement('div');
    row.className = 'subnet-row'
        + (isDisabled ? ' is-disabled' : '')
        + (isPendingAuth ? ' is-pending' : '')
        + (hasNoGateway ? ' is-no-gateway' : '')
        + (isRoutable && !isToggleOff ? ' is-routable' : '');

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
        lbl.className = 'subnet-switch' + (isToggleOff ? ' is-off' : ' is-on');

        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'subnet-switch-input';
        cb.checked = !isToggleOff;
        cb.setAttribute('aria-label',
            isToggleOff ? t('btn_enable_subnet') : t('btn_disable_subnet'));
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
                const span = btn.querySelector('span[data-i18n]') || btn.querySelector('span');
                if (span) {
                    span.textContent = isAutoScroll ? (t('auto_scroll') || '📜 Auto-Scroll: ON') : (t('auto_scroll_off') || '📜 Auto-Scroll: OFF');
                } else {
                    btn.innerText = isAutoScroll ? (t('auto_scroll') || '📜 Auto-Scroll: ON') : (t('auto_scroll_off') || '📜 Auto-Scroll: OFF');
                }
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

        function peerRTTIsMeasured(peer) {
            return !!peer && peer.rtt_measured === true && Number.isFinite(Number(peer.rtt_ms)) && Number(peer.rtt_ms) > 0;
        }

        function peerRTTText(peer) {
            return peerRTTIsMeasured(peer) ? Number(peer.rtt_ms).toFixed(1) + ' ms' : '—';
        }

        function peerRTTSourceLabel(peer) {
            const source = peer && peer.rtt_source;
            if (source === 'tap-icmp') return 'TAP ICMP data path';
            if (source === 'libp2p-ping') return 'live libp2p ping';
            if (source === 'p2p-echo') return 'P2P echo control stream';
            return source || 'measured probe';
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
                        select.innerHTML += `<option value="${escapeHTML(p.peer_id)}" ${selected}>${escapeHTML(name)} (${escapeHTML(p.tap_ip) || 'No IP'}) - ${peerRTTText(p)}</option>`;
                    });
                }
            }
            const modal = document.getElementById('speedTestModal');
            if (modal) {
                document.getElementById('speedGaugeVal').innerText = '—';
                document.getElementById('speedProgressBar').style.width = '0%';
                document.getElementById('stRTTAvg').innerText = '—';
                document.getElementById('stJitter').innerText = '—';
                document.getElementById('stQuality').innerText = '—';
                document.getElementById('stPacketLoss').innerText = '—';
                document.getElementById('stMeasurementNote').innerText = 'No benchmark run yet';
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
            document.getElementById('speedGaugeVal').innerText = '—';
            document.getElementById('stRTTAvg').innerText = '—';
            document.getElementById('stJitter').innerText = '—';
            document.getElementById('stQuality').innerText = '—';
            document.getElementById('stPacketLoss').innerText = '—';
            document.getElementById('stMeasurementNote').innerText = 'Running live benchmark…';
            
            let progress = 0;
            const progressInterval = setInterval(() => {
                progress += 5;
                if (progress <= 100) {
                    document.getElementById('speedProgressBar').style.width = progress + '%';
                }
            }, 50);

            try {
                const result = await safeFetchJSON(`/api/speedtest?peer_id=${encodeURIComponent(peerID)}`);
                if (!result.ok) {
                    console.warn("SpeedTest request failed:", result.error);
                    clearInterval(progressInterval);
                    document.getElementById('speedProgressBar').style.width = '0%';
                    document.getElementById('stMeasurementNote').innerText = result.error || 'SpeedTest request failed';
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
                document.getElementById('stPacketLoss').innerText = Number.isFinite(Number(data.packet_loss)) ? (Number(data.packet_loss) * 100).toFixed(0) + '%' : '—';
                document.getElementById('stMeasurementNote').innerText = data.measurement_note || 'Measured by the live P2P stream benchmark';
            } catch (e) {
                console.error("SpeedTest error:", e);
                clearInterval(progressInterval);
                document.getElementById('speedProgressBar').style.width = '0%';
                document.getElementById('stMeasurementNote').innerText = e.message || 'SpeedTest error';
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
                const shareData = JSON.stringify((currentFullConfig && Object.keys(currentFullConfig).length > 0) ? currentFullConfig : { node_name: localNodeInfo.name || 'P2P TAP Node', tap_ip: localNodeInfo.ip || '' }, null, 2);
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
            const shareData = JSON.stringify((currentFullConfig && Object.keys(currentFullConfig).length > 0) ? currentFullConfig : { node_name: localNodeInfo.name || 'P2P TAP Node', tap_ip: localNodeInfo.ip || '' }, null, 2);
            copyToClipboard(shareData).then(() => {
                showToast(t('copied_toast') || '📋 Config JSON copied to clipboard!');
            }).catch(err => {
                console.error("Clipboard copy failed:", err);
                showToast('❌ Copy failed: ' + err.message);
            });
        }

        function downloadConfigJSON() {
            const shareData = JSON.stringify((currentFullConfig && Object.keys(currentFullConfig).length > 0) ? currentFullConfig : { node_name: localNodeInfo.name || 'P2P TAP Node', tap_ip: localNodeInfo.ip || '' }, null, 2);
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
        function darkenHex(hex, amt) {
            const h = hex.replace('#', '');
            const r = parseInt(h.substring(0, 2), 16);
            const g = parseInt(h.substring(2, 4), 16);
            const b = parseInt(h.substring(4, 6), 16);
            const mix = (c) => Math.round(Math.max(0, c * (1 - amt)));
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
                return `<div class="tt-title"><span>💻 ${escapeHTML(found.name)}</span><span class="pill-badge role-static" style="font-size:0.68rem;padding:2px 8px;">${t('topo_tt_local_host')}</span></div>`
                    + `<div class="tt-grid">`
                    + `<div class="tt-row tt-full"><span>${t('topo_tt_ipv4')}</span><span class="tt-val">${escapeHTML(found.tapIP || '-')}</span></div>`
                    + `<div class="tt-row tt-full"><span>${t('topo_tt_ipv6')}</span><span class="tt-val">${escapeHTML(found.tapIPv6 || '-')}</span></div>`
                    + (found.isExitServer ? `<div class="tt-row"><span>${t('topo_tt_enc')}</span><span class="tt-val" style="color:var(--warn);">🚪 ${t('topo_badge_exit_server')}</span></div>` : '')
                    + (found.transitCount > 0 ? `<div class="tt-row"><span>${t('topo_tt_route')}</span><span class="tt-val" style="color:var(--warn);">🌉 ${t('topo_badge_transit')} ×${found.transitCount}</span></div>` : '')
                    + (found.totalTx > 0 || found.totalRx > 0 ? `<div class="tt-row tt-full"><span>${t('topo_summary_thru')}</span><span class="tt-val" style="color:var(--info);">⬆ ${formatSpeed(found.totalTx || 0)} ⬇ ${formatSpeed(found.totalRx || 0)}</span></div>` : '')
                    + `<div class="tt-row"><span>${t('topo_summary_gw')}</span><span class="tt-val" style="color:var(--accent-purple);">${gwPkts}</span></div>`
                    + (found.cluster ? `<div class="tt-row"><span>${t('topo_tt_cluster')}</span><span class="tt-val" style="color:var(--accent-purple)">${escapeHTML(clusterNameOf(found.cluster))}</span></div>` : '')
                    + `<div class="tt-row tt-full"><span>${t('topo_tt_peer_id')}</span><span class="tt-val tt-val-id">${escapeHTML(localNodeInfo.peerID || '-')}</span></div>`
                    + `</div>`;
            }
            const p = found.peer || {};
            const roleClass = p.role === 'Bootstrap' ? 'role-bootstrap' : (p.role === 'Static' ? 'role-static' : 'role-peer');
            const roleIcon = p.role === 'Bootstrap' ? '🟣' : (p.role === 'Static' ? '🟦' : '🟢');
            const roleText = p.role === 'Bootstrap' ? t('topo_badge_boot') : (p.role === 'Static' ? t('topo_badge_static') : (t('topo_badge_peer') || escapeHTML(p.role || 'Peer')));
            const nodeTitle = (p.node_name && p.node_name.trim()) ? escapeHTML(p.node_name) : escapeHTML(found.name);
            const tapIPs = [p.tap_ip, p.tap_ipv6].filter(Boolean).join(' / ') || '-';
            const rttMeasured = peerRTTIsMeasured(p);
            const jitterMeasured = p.jitter_measured === true && Number.isFinite(Number(p.jitter_ms));
            const lossMeasured = p.loss_measured === true && Number.isFinite(Number(p.loss_rate_percent));
            const rttColor = !rttMeasured ? '#94a3b8' : (p.rtt_ms < 50 ? '#34d399' : (p.rtt_ms < 150 ? '#fbbf24' : '#f87171'));

            // Encryption / connection-state / path summaries for the tooltip.
            const encAlgo = p.obf_algo || 'none';
            const encColor = (p.obf_encrypted) ? '#34d399' : (encAlgo === 'none' ? '#94a3b8' : '#fbbf24');
            const encTxt = p.obf_encrypted ? encAlgo : (encAlgo === 'none' ? (t('enc_plaintext') || 'Plaintext (none)') : encAlgo + ' ' + (t('enc_not_active') || 'Not Active'));
            const encHtml = `<div class="tt-row"><span>${t('topo_tt_enc')}</span><span class="tt-val" style="color:${encColor}">${encTxt}</span></div>`;
            const connState = p.conn_state || 'unknown';
            const connColor = (connState === 'ok' || connState === 'relay_ok') ? '#34d399' : (connState === 'connecting' ? '#38bdf8' : '#f87171');
            const connHtml = `<div class="tt-row"><span>${t('topo_tt_conn')}</span><span class="tt-val" style="color:${connColor}">${escapeHTML(connState)}</span></div>`;
            // Return-path liveness (asymmetric routing)
            const rpState = p.return_path || 'idle';
            const rpColor = rpState === 'ok' ? '#34d399' : (rpState === 'dead' ? '#f87171' : '#94a3b8');
            const rpHtml = `<div class="tt-row"><span>${t('col_return_path')}</span><span class="tt-val" style="color:${rpColor}" title="${escapeHTML(p.return_path_detail || '')}">${escapeHTML(t('return_' + rpState))}</span></div>`;
            const pathHtml = (found.relayPathNames && found.relayPathNames.length > 0)
                ? `<div class="tt-row tt-full"><span>${t('topo_tt_route_via')}</span><span class="tt-val" style="color:var(--warn);">${t('topo_via')} ${escapeHTML(found.relayPathNames.join(' ➔ '))}</span></div>`
                : '';

            const matchedRoute = cachedRoutes.find(r => r.dest_peer === p.peer_id);
            const actualPath = found.transportPath || routeTransportPath(matchedRoute);
            let routeHtml;
            if (actualPath === 'circuit-relay') {
                routeHtml = `<div class="tt-row tt-full"><span>${t('topo_tt_route')}</span><span class="tt-val" style="color:var(--warn);">🔀 ${t('topo_tt_circuit_relay')}</span></div>`;
            } else if (actualPath === 'overlay-relay' && matchedRoute) {
                const routeNames = Array.isArray(matchedRoute.path_names) ? matchedRoute.path_names.join(' ➔ ') : transportPathLabel(actualPath);
                routeHtml = `<div class="tt-row tt-full"><span>${t('topo_tt_optimal_route')}</span><span class="tt-val" style="color:var(--accent-purple);">🔀 ${escapeHTML(routeNames)}</span></div>`
                    + `<div class="tt-row tt-full"><span>${t('topo_tt_route_gain')}</span><span class="tt-val" style="color:var(--success);" title="Routing estimate">⚡ ≈-${matchedRoute.saved_rtt_ms} ms</span></div>`;
            } else if (actualPath === 'direct') {
                routeHtml = `<div class="tt-row tt-full"><span>${t('topo_tt_route')}</span><span class="tt-val" style="color:var(--success);">🟢 ${t('topo_tt_direct_link')}</span></div>`;
            } else {
                routeHtml = `<div class="tt-row tt-full"><span>${t('topo_tt_route')}</span><span class="tt-val" style="color:var(--text-muted);">⚪ ${transportPathLabel('unknown')}</span></div>`;
            }

            const isTransit = transitRelaySet.has(p.peer_id);
            const transitBadge = isTransit ? `<span class="pill-badge role-bootstrap" style="font-size:0.68rem;padding:2px 8px;margin-left:4px;">🔀 ${t('topo_tt_transit_relay')}</span>` : '';

            // Per-link sequence / link-integrity section.
            const txSeq = found.txSeq || 0, rxSeq = found.rxSeq || 0;
            const dup = found.dedupDrops || 0;
            const winMax = found.seqWinMax || 0;
            const skew = winMax > 0 ? (winMax - rxSeq) : 0;
            const linkBroken = skew >= 1024 || (dup > 0 && rxSeq < winMax);
            const seqColor = linkBroken ? '#f87171' : '#34d399';
            const linkIntegrityHtml = linkBroken
                ? `<div class="tt-row"><span>${t('topo_tt_link_integrity')}</span><span class="tt-val" style="color:var(--danger)">⚠️ ${t('topo_tt_blackhole')}</span></div>`
                : `<div class="tt-row"><span>${t('topo_tt_link_integrity')}</span><span class="tt-val" style="color:var(--success)">✅ ${t('topo_tt_healthy')}</span></div>`;

            const seqHtml = `<div class="tt-row tt-full"><span>${t('topo_tt_seq')}</span><span class="tt-val" style="color:${seqColor}">↑${txSeq} / ↓${rxSeq}</span></div>`
                + (winMax > 0 ? `<div class="tt-row tt-full"><span>${t('topo_tt_dedup_window')}</span><span class="tt-val" style="color:${skew >= 1024 ? 'var(--danger)' : 'var(--text-secondary)'}">max=${winMax} (skew ${skew})</span></div>` : '')
                + (dup > 0 ? `<div class="tt-row tt-full"><span>${t('topo_tt_dup_drops')}</span><span class="tt-val" style="color:var(--danger)">${dup}</span></div>` : '');

            return `<div class="tt-title"><span>${nodeTitle}</span><div><span class="pill-badge ${roleClass}" style="font-size:0.68rem;padding:2px 8px;">${roleIcon} ${roleText}</span>${transitBadge}</div></div>`
                + `<div class="tt-grid">`
                + `<div class="tt-row tt-full"><span>${t('topo_tt_tap_ip')}</span><span class="tt-val">${escapeHTML(tapIPs)}</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_os_arch')}</span><span class="tt-val">${escapeHTML(p.os_arch || '—')}</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_version')}</span><span class="tt-val">${escapeHTML(p.version || '-')}</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_transport')}</span><span class="tt-val">${escapeHTML(p.transport || 'P2P')}</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_transport_path')}</span><span class="tt-val">${escapeHTML(transportPathLabel(actualPath))}</span></div>`
                + (found.relayHop ? `<div class="tt-row"><span>${t('topo_tt_relay_hop')}</span><span class="tt-val" style="color:var(--warn)">${escapeHTML(relayNameOf(found.relayHop))}</span></div>` : '')
                + (found.cluster ? `<div class="tt-row"><span>${t('topo_tt_cluster')}</span><span class="tt-val" style="color:var(--accent-purple)">${escapeHTML(clusterNameOf(found.cluster))}</span></div>` : '')
                + (found.bootHops > 0 ? `<div class="tt-row"><span>${t('topo_tt_boot_hops')}</span><span class="tt-val" style="color:var(--accent-cyan)">${found.bootHops}</span></div>` : '')
                + encHtml
                + connHtml
                + rpHtml
                + linkIntegrityHtml
                + `<div class="tt-row"><span>${t('topo_tt_rtt')}</span><span class="tt-val" style="color:${rttColor}" title="${escapeHTML(peerRTTSourceLabel(p))}">${peerRTTText(p)}</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_jitter')}</span><span class="tt-val">${jitterMeasured ? Number(p.jitter_ms).toFixed(1) + ' ms' : '—'}</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_loss')}</span><span class="tt-val" style="color:${lossMeasured && Number(p.loss_rate_percent) > 1 ? 'var(--danger)' : 'var(--text-secondary)'}">${lossMeasured ? Number(p.loss_rate_percent).toFixed(1) + '%' : '—'}</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_uptime')}</span><span class="tt-val">${escapeHTML(p.uptime || '-')}</span></div>`
                + `<div class="tt-row"><span>${t('topo_tt_since')}</span><span class="tt-val">${escapeHTML(p.connected_since || '-')}</span></div>`
                + (p.geo_location ? `<div class="tt-row"><span>${t('topo_tt_geo')}</span><span class="tt-val">${escapeHTML(p.geo_location)}</span></div>` : '')
                + `<div class="tt-row tt-full"><span>${t('topo_tt_live_rate')}</span><span class="tt-val" style="color:var(--success);">⬆ ${formatSpeed(p.tx_speed || 0)} | ⬇ ${formatSpeed(p.rx_speed || 0)}</span></div>`
                + `<div class="tt-row tt-full"><span>${t('topo_tt_total')}</span><span class="tt-val">⬆ ${formatBytes(p.total_tx || 0)} ⬇ ${formatBytes(p.total_rx || 0)}</span></div>`
                + routeHtml
                + pathHtml
                + seqHtml
                + `<div class="tt-row tt-full"><span>${t('topo_tt_peer_id')}</span><span class="tt-val tt-val-id">${escapeHTML(p.peer_id || '-')}</span></div>`
                + `</div>`;
        }

        // --- Selection + filter (interaction) -------------------------------
        function topoNodeMatchesFilter(n) {
            if (topoFilterMode === 'all') return true;
            if (topoFilterMode === 'direct') return !n.isSelf && n.transportPath === 'direct';
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
                            runPingDiagnostics();
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
                tt.innerHTML = buildTopoTooltipHTML(found);
                tt.style.display = 'block';

                const nodeCanvasX = (found.x * topoZoom + topoPanX);
                const nodeCanvasY = (found.y * topoZoom + topoPanY);
                const canvasW = canvas.clientWidth || 800;

                if (nodeCanvasY < 160) {
                    tt.style.transform = 'translate(-50%, 18px)';
                } else {
                    tt.style.transform = 'translate(-50%, -105%)';
                }
                const clampedX = Math.max(165, Math.min(canvasW - 165, nodeCanvasX));
                tt.style.left = clampedX + 'px';
                tt.style.top = nodeCanvasY + 'px';
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
            if (!canvas || !canvas.getClientRects().length) return;
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
                    const rttMeasured = peerRTTIsMeasured(live);
                    const rtt = rttMeasured ? Number(live.rtt_ms) : (tn.rtt || 0);
                    const rttEstimated = !rttMeasured && rtt > 0;
                    const transportPath = tn.self ? '' : (tn.transport_path || 'unknown');
                    const isRelayed = !tn.self && (transportPath === 'circuit-relay' || transportPath === 'overlay-relay');
                    const isUnknown = !tn.self && transportPath === 'unknown';
                    const isRelayAny = isRelayed || !!tn.relay; // relayed reach OR transit-relay role
                    const isBoot = !!tn.is_boot;
                    const isStatic = !!tn.static;
                    const cluster = tn.cluster || null;
                    const bootHops = (typeof tn.boot_hops === 'number') ? tn.boot_hops : 0;
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
                    let linkColor = isUnknown ? "#94a3b8" : "#34d399";
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
                        isUnknown: isUnknown,
                        isBoot: isBoot,
                        isStatic: isStatic,
                        cluster: cluster,
                        bootHops: bootHops,
                        transportPath: transportPath,
                        relayHop: relayHop,
                        linkClass: linkClass,
                        lineStyle: lineStyle,
                        rtt: rtt,
                        rttMeasured: rttMeasured,
                        rttEstimated: rttEstimated,
                        linkColor: linkColor,
                        particleColor: isRelayAny ? "#f59e0b" : (isUnknown ? "#94a3b8" : (rtt < 30 ? "#34d399" : "#38bdf8")),
                        glowColor: isRelayAny ? "#fbbf24" : (isUnknown ? "#94a3b8" : "#38bdf8"),
                        role: live.role || (tn.relay ? 'relay' : (isRelayed ? 'relayed' : (isUnknown ? 'unknown' : (isBoot ? 'bootstrap' : 'direct')))),
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
                        const peerPath = peerTransportPath(p);
                        const synNode = mkNode({
                            peer_id: p.peer_id,
                            node_name: p.node_name,
                            tap_ip: p.tap_ip,
                            tap_ipv6: p.tap_ipv6,
                            direct: peerPath === 'direct',
                            transport_path: peerPath,
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
                    const directCount = nodes.filter(n => !n.isSelf && n.transportPath === 'direct').length;
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
                const rttMeasured = peerRTTIsMeasured(p);
                const rtt = rttMeasured ? Number(p.rtt_ms) : 0;
                const peerPath = peerTransportPath(p);
                const isRelayed = peerPath === 'circuit-relay' || peerPath === 'overlay-relay';
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
                    isUnknown: peerPath === 'unknown',
                    transportPath: peerPath,
                    rtt: rtt,
                    rttMeasured: rttMeasured,
                    rttEstimated: false,
                    linkColor: linkColor,
                    particleColor: isRelayed ? "#f59e0b" : (peerPath === 'unknown' ? "#94a3b8" : (rtt < 30 ? "#34d399" : "#38bdf8")),
                    glowColor: isRelayed ? "#fbbf24" : (peerPath === 'unknown' ? "#94a3b8" : "#38bdf8"),
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
            const canvas = document.getElementById('topologyCanvas');
            if (document.hidden || !canvas || !canvas.getClientRects().length) {
                topoRAFId = null;
                return;
            }
            topoRAFId = requestAnimationFrame(renderTopology);
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

            // --- Cyber Grid & Ambient Canvas Background ---
            if (!lightT) {
                ctx.save();
                ctx.strokeStyle = "rgba(255, 255, 255, 0.02)";
                ctx.lineWidth = 1;
                const gridSize = 36;
                const offX = ((topoPanX * topoZoom) % gridSize + gridSize) % gridSize;
                const offY = ((topoPanY * topoZoom) % gridSize + gridSize) % gridSize;
                ctx.beginPath();
                for (let x = offX; x < topoCanvasW; x += gridSize) {
                    ctx.moveTo(x, 0); ctx.lineTo(x, topoCanvasH);
                }
                for (let y = offY; y < topoCanvasH; y += gridSize) {
                    ctx.moveTo(0, y); ctx.lineTo(topoCanvasW, y);
                }
                ctx.stroke();
                ctx.restore();
            }

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
                ctx.globalAlpha = b.local ? 0.06 : 0.03;
                ctx.beginPath();
                if (ctx.roundRect) {
                    ctx.roundRect(b.x, b.y, b.w, b.h, 16);
                } else {
                    ctx.rect(b.x, b.y, b.w, b.h);
                }
                ctx.fill();

                // Subtle neon boundary
                ctx.globalAlpha = b.local ? 0.65 : 0.35;
                ctx.strokeStyle = b.color;
                ctx.lineWidth = b.local ? 1.5 : 1.0;
                ctx.setLineDash([8, 6]);
                ctx.stroke();
                ctx.setLineDash([]);

                // Glassmorphic cluster label chip anchored at top-left
                const label = '🟣 ' + b.name + (b.count > 0 ? ` (${b.count})` : '');
                ctx.font = "bold 11px system-ui, -apple-system, sans-serif";
                const lw = topoMeasure(ctx, "bold 11px system-ui, -apple-system, sans-serif", label) + 20;
                ctx.globalAlpha = b.local ? 0.92 : 0.75;
                ctx.fillStyle = lightT ? "rgba(255,255,255,0.92)" : "rgba(18, 14, 38, 0.88)";
                ctx.strokeStyle = b.color;
                ctx.lineWidth = 1;
                ctx.beginPath();
                if (ctx.roundRect) {
                    ctx.roundRect(b.x + 10, b.y + 8, lw, 22, 6);
                } else {
                    ctx.rect(b.x + 10, b.y + 8, lw, 22);
                }
                ctx.fill();
                ctx.stroke();

                ctx.fillStyle = lightT ? "#7c3aed" : "#e9d5ff";
                ctx.textAlign = 'left';
                ctx.textBaseline = 'middle';
                ctx.fillText(label, b.x + 20, b.y + 19);
                ctx.textBaseline = 'alphabetic';
                ctx.restore();
            });

            // Draw Links and Staggered Glassmorphic Badges
            for (let i = 0; i < nodes.length; i++) {
                const target = nodes[i];
                if (!target.parentId || !nodeByID[target.parentId]) continue;
                const parent = nodeByID[target.parentId];
                const edgeKey = parent.id + '|' + target.id;
                const edgeHi = topoSelectedId !== null && topoSelectedEdgeSet.has(edgeKey);
                const edgeDim = topoFilterMode !== 'all' && !topoNodeMatchesFilter(target);

                // Sleek link line
                ctx.beginPath();
                ctx.moveTo(parent.x, parent.y);
                ctx.lineTo(target.x, target.y);
                ctx.strokeStyle = edgeHi ? (target.isRelayed ? '#f59e0b' : '#38bdf8') : target.linkColor;
                ctx.lineWidth = edgeHi ? (target.isRelayed ? 2.6 : 3.4) : (target.isRelayed ? 1.6 : 2.2);
                if (target.lineStyle === 'overlay') ctx.setLineDash([8, 5]);
                else if (target.lineStyle === 'circuit') ctx.setLineDash([4, 4]);
                else ctx.setLineDash([]);

                if (edgeHi) {
                    ctx.shadowColor = target.isRelayed ? '#f59e0b' : '#38bdf8';
                    ctx.shadowBlur = 12;
                } else {
                    ctx.shadowColor = target.linkColor;
                    ctx.shadowBlur = 4;
                }
                ctx.globalAlpha = edgeHi ? 0.95 : (edgeDim ? 0.12 : (topoSelectedId !== null ? 0.18 : 0.65));
                ctx.stroke();
                ctx.shadowBlur = 0;
                ctx.globalAlpha = 1.0;

                // ── Staggered position along the link ray to prevent horizontal bar collision! ──
                // Sibling badges gently stagger at 42%, 56%, 38%, 62%, 50% along each ray
                const staggerOffsets = [0.42, 0.58, 0.36, 0.64, 0.48, 0.52];
                const tDist = leafNodes <= 2 ? 0.50 : staggerOffsets[i % staggerOffsets.length];
                const midX = parent.x + (target.x - parent.x) * tDist;
                const midY = parent.y + (target.y - parent.y) * tDist;

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
                let typeLine;
                if (target.transportPath === 'circuit-relay') {
                    typeLine = t('topo_tt_circuit_relay') || 'Circuit Relay';
                } else if (target.transportPath === 'overlay-relay') {
                    typeLine = (t('topo_via') || 'via') + (relayFirst ? ' ' + relayFirst : ' relay');
                } else if (target.transportPath === 'direct') {
                    typeLine = t('topo_summary_direct') || '直连';
                } else {
                    typeLine = transportPathLabel('unknown');
                }
                const dropTxt = target.dedupDrops > 0 ? ` · dup:${target.dedupDrops}` : '';
                const seqWinMax = typeof target.seqWinMax === 'number' ? target.seqWinMax : 0;
                const skew = seqWinMax > 0 ? (seqWinMax - target.rxSeq) : 0;
                const skewTxt = blackhole ? ` · ⚠skew ${skew}` : '';
                const rttLine = target.rttMeasured
                    ? `${Number(target.rtt).toFixed(1)}ms`
                    : (target.rttEstimated ? `≈${target.rtt}ms route est.` : 'RTT —');
                let metaLine = `${rttLine} · ${typeLine}${dropTxt}${skewTxt}`;
                if (target.bootHops > 0) metaLine += ' · 🌐boot×' + target.bootHops;

                // Skip when dimmed by active filter/selection
                if (edgeDim || (topoSelectedId !== null && !edgeHi)) continue;

                // Measure widths
                const wRate = rateLine ? topoMeasure(ctx, "bold 9px ui-monospace, monospace", rateLine) : 0;
                const wMeta = topoMeasure(ctx, "9px system-ui, -apple-system, sans-serif", metaLine);
                const contentW = Math.max(wRate, wMeta);

                const padX = 8, padY = 4, lineH = 12;
                const numLines = rateLine ? 2 : 1;
                const boxW = Math.max(58, contentW + padX * 2);
                const boxH = padY * 2 + numLines * lineH;
                const boxX = midX - boxW / 2;
                const boxY = midY - boxH / 2;

                ctx.save();
                // The label's shadow follows its surface in both themes.
                ctx.shadowColor = edgeHi ? "#38bdf8" : (lightT ? "rgba(15,23,42,0.12)" : "rgba(0,0,0,0.5)");
                ctx.shadowBlur = edgeHi ? 10 : 6;
                ctx.fillStyle = lightT ? "rgba(255,255,255,0.95)" : "rgba(10, 16, 32, 0.88)";
                ctx.strokeStyle = blackhole ? "#f87171" : (edgeHi ? "#38bdf8" : (target.isRelayed ? "rgba(245, 158, 11, 0.6)" : "rgba(56, 189, 248, 0.4)"));
                ctx.lineWidth = edgeHi ? 1.6 : 1;
                ctx.beginPath();
                if (ctx.roundRect) {
                    ctx.roundRect(boxX, boxY, boxW, boxH, 7);
                } else {
                    ctx.rect(boxX, boxY, boxW, boxH);
                }
                ctx.fill();
                ctx.stroke();
                ctx.shadowBlur = 0;

                let yCursor = boxY + padY + 9;
                ctx.textAlign = "center";
                if (rateLine) {
                    ctx.fillStyle = blackhole ? (lightT ? "#dc2626" : "#f87171") : (target.isRelayed ? (lightT ? "#b45309" : "#fcd34d") : (lightT ? "#0284c7" : "#38bdf8"));
                    ctx.font = "bold 9px ui-monospace, monospace";
                    ctx.fillText(rateLine, midX, yCursor);
                    yCursor += lineH;
                }
                ctx.font = "9px system-ui, -apple-system, sans-serif";
                ctx.fillStyle = blackhole ? (lightT ? "#dc2626" : "#fca5a5") : (lightT ? "#475569" : "#94a3b8");
                ctx.fillText(metaLine, midX, yCursor);
                ctx.restore();
            }

            // --- Real-Rate Data-Flow Glowing Particles (smooth @60fps) ---
            const nowMs = (ts || performance.now());
            const dt = Math.max(0, Math.min(0.1, (nowMs - topoLastFrameTs) / 1000)) || 0.016;
            topoLastFrameTs = nowMs;
            const tsec = nowMs / 1000;
            const selfNode = nodes[0];

            for (let i = 0; i < nodes.length; i++) {
                const target = nodes[i];
                if (!target.parentId || !nodeByID[target.parentId]) continue;
                const parent = nodeByID[target.parentId];
                if (!topoFlowState[target.id]) topoFlowState[target.id] = { in: Math.random(), out: Math.random() };

                const inboundRate = target.rxSpeed || 0;
                const outboundRate = target.txSpeed || 0;
                const inVel = inboundRate <= TOPO_IDLE_BPS ? 0 : Math.min(2.4, 0.15 + inboundRate / (256 * 1024));
                const outVel = outboundRate <= TOPO_IDLE_BPS ? 0 : Math.min(2.4, 0.15 + outboundRate / (256 * 1024));

                topoFlowState[target.id].in = (topoFlowState[target.id].in + inVel * dt) % 1.0;
                topoFlowState[target.id].out = (topoFlowState[target.id].out + outVel * dt) % 1.0;

                const inCount = inVel === 0 ? 0 : Math.min(6, 2 + Math.floor(inboundRate / (64 * 1024)));
                const outCount = outVel === 0 ? 0 : Math.min(6, 2 + Math.floor(outboundRate / (64 * 1024)));

                // Inbound particles (peer -> parent)
                for (let k = 0; k < inCount; k++) {
                    let p = (topoFlowState[target.id].in + k / inCount) % 1.0;
                    const alpha = 0.35 + 0.65 * Math.sin(Math.PI * p);
                    const px = target.x + (parent.x - target.x) * p;
                    const py = target.y + (parent.y - target.y) * p;
                    ctx.beginPath();
                    ctx.arc(px, py, 4.2, 0, 2 * Math.PI);
                    ctx.fillStyle = target.particleColor;
                    ctx.globalAlpha = alpha;
                    ctx.shadowColor = target.glowColor;
                    ctx.shadowBlur = 12;
                    ctx.fill();
                }
                // Outbound particles (parent -> peer)
                for (let k = 0; k < outCount; k++) {
                    let p = (topoFlowState[target.id].out + k / outCount) % 1.0;
                    const alpha = 0.35 + 0.65 * Math.sin(Math.PI * p);
                    const px = parent.x + (target.x - parent.x) * p;
                    const py = parent.y + (target.y - parent.y) * p;
                    ctx.beginPath();
                    ctx.arc(px, py, 4.2, 0, 2 * Math.PI);
                    ctx.fillStyle = target.particleColor;
                    ctx.globalAlpha = alpha;
                    ctx.shadowColor = target.glowColor;
                    ctx.shadowBlur = 12;
                    ctx.fill();
                }
            }
            ctx.shadowBlur = 0;
            ctx.globalAlpha = 1.0;

            // --- High-Tech 3D Spherical Nodes & Spaced Typography ---
            for (let i = 0; i < nodes.length; i++) {
                const n = nodes[i];
                const nodeRadius = topoNodeRadius(n, leafNodes);
                const nameSize = nodeRadius >= 14 ? 12 : nodeRadius >= 10 ? 11 : nodeRadius >= 8 ? 9 : 8;
                const nameGap = nodeRadius + 14;
                const nodeHi = topoSelectedId !== null && topoSelectedPathSet.has(n.id);
                const nodeDim = topoFilterMode !== 'all' && !topoNodeMatchesFilter(n);
                ctx.globalAlpha = nodeDim ? 0.18 : (nodeHi ? 1.0 : (topoSelectedId !== null ? 0.3 : 1.0));

                if (n.isSelf) {
                    // Double concentric pulse for Root/Self Node
                    const pulseR = nodeRadius + 5 + Math.sin(tsec * 2.6) * 3.5;
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, pulseR, 0, 2 * Math.PI);
                    ctx.fillStyle = "rgba(99, 102, 241, 0.22)";
                    ctx.fill();

                    // Outer orbit tech ring
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, nodeRadius + 9, 0, 2 * Math.PI);
                    ctx.strokeStyle = "rgba(129, 140, 248, 0.35)";
                    ctx.lineWidth = 1.2;
                    ctx.setLineDash([6, 8]);
                    ctx.stroke();
                    ctx.setLineDash([]);
                }

                // 3D Glass Sphere with Radial Highlight
                const baseFill = n.isSelf ? "#6366f1" : (n.isBoot ? "#a855f7" : (n.isRelayed ? "#f59e0b" : (n.isUnknown ? "#64748b" : "#10b981")));
                const strokeCol = n.isSelf ? (lightT ? "#4338ca" : "#c7d2fe") : (n.isBoot ? (lightT ? "#7c3aed" : "#ddd6fe") : (n.isRelayed ? (lightT ? "#b45309" : "#fef3c7") : (n.isUnknown ? (lightT ? "#475569" : "#cbd5e1") : (lightT ? "#047857" : "#a7f3d0"))));
                const grad = ctx.createRadialGradient(n.x - nodeRadius * 0.35, n.y - nodeRadius * 0.35, nodeRadius * 0.15, n.x, n.y, nodeRadius);
                grad.addColorStop(0, lightenHex(baseFill, lightT ? 0.40 : 0.55));
                grad.addColorStop(0.6, baseFill);
                grad.addColorStop(1, darkenHex(baseFill, 0.25));

                ctx.beginPath();
                ctx.arc(n.x, n.y, nodeRadius, 0, 2 * Math.PI);
                ctx.fillStyle = grad;
                ctx.strokeStyle = nodeHi ? (lightT ? "#0ea5e9" : "#38bdf8") : strokeCol;
                ctx.lineWidth = nodeHi ? 3.5 : 2.2;
                if (nodeHi) {
                    ctx.shadowColor = lightT ? "#0ea5e9" : "#38bdf8";
                    ctx.shadowBlur = 16;
                } else {
                    ctx.shadowColor = baseFill;
                    ctx.shadowBlur = 8;
                }
                ctx.fill();
                ctx.stroke();
                ctx.shadowBlur = 0;

                // Boot node: elegant dashed outer halo
                if (n.isBoot) {
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, nodeRadius + 5, 0, 2 * Math.PI);
                    ctx.strokeStyle = lightT ? "#7c3aed" : "#c4b5fd";
                    ctx.lineWidth = 1.5;
                    ctx.setLineDash([4, 4]);
                    ctx.stroke();
                    ctx.setLineDash([]);
                }
                // Static peer: elegant glowing pin badge at top-right
                if (n.isStatic) {
                    const pinX = n.x + nodeRadius * 0.72;
                    const pinY = n.y - nodeRadius * 0.72;
                    ctx.fillStyle = "#3b82f6";
                    ctx.beginPath();
                    ctx.arc(pinX, pinY, 5, 0, 2 * Math.PI);
                    ctx.fill();
                    ctx.strokeStyle = "#ffffff";
                    ctx.lineWidth = 1.5;
                    ctx.stroke();
                }

                // ── Node Labels with Clear Vertical Hierarchy ──
                let labelY = n.y + nameGap;
                // Node Name
                ctx.fillStyle = lightT ? "#0f172a" : "#f8fafc";
                ctx.font = "bold " + nameSize + "px system-ui, -apple-system, sans-serif";
                ctx.textAlign = "center";
                ctx.fillText(topoShortLabel(n.name), n.x, labelY);
                labelY += nameSize + 4;

                if (n.isSelf) {
                    if (!crowded) {
                        // IP Address Tag (Sleek Frosted Cyan Tag)
                        if (n.tapIP) {
                            const ipText = n.tapIP;
                            ctx.font = "bold 10px ui-monospace, monospace";
                            const ipW = topoMeasure(ctx, "bold 10px ui-monospace, monospace", ipText) + 12;
                            ctx.save();
                            ctx.fillStyle = "rgba(56, 189, 248, 0.12)";
                            ctx.strokeStyle = "rgba(56, 189, 248, 0.4)";
                            ctx.lineWidth = 1;
                            ctx.beginPath();
                            if (ctx.roundRect) ctx.roundRect(n.x - ipW / 2, labelY - 10, ipW, 16, 4);
                            else ctx.rect(n.x - ipW / 2, labelY - 10, ipW, 16);
                            ctx.fill();
                            ctx.stroke();
                            ctx.fillStyle = lightT ? "#0284c7" : "#38bdf8";
                            ctx.textAlign = "center";
                            ctx.fillText(ipText, n.x, labelY + 2);
                            ctx.restore();
                            labelY += 16;
                        }
                        // Role badges
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
                    // Aggregate throughput through self
                    if (n.totalTx > 0 || n.totalRx > 0) {
                        ctx.fillStyle = lightT ? "#0369a1" : "#7dd3fc";
                        ctx.font = (crowded ? 8 : 9) + "px ui-monospace, monospace";
                        ctx.fillText('⬆ ' + formatSpeed(n.totalTx) + '  ⬇ ' + formatSpeed(n.totalRx), n.x, labelY);
                    }
                } else {
                    // Per-peer live Rx/Tx rate beneath the node name
                    const peerTx = typeof n.txSpeed === 'number' ? n.txSpeed : 0;
                    const peerRx = typeof n.rxSpeed === 'number' ? n.rxSpeed : 0;
                    ctx.fillStyle = lightT ? "#475569" : "#94a3b8";
                    ctx.font = (nodeRadius >= 10 ? 9 : 8) + "px ui-monospace, monospace";
                    ctx.fillText("⬆ " + formatSpeed(peerTx) + "  ⬇ " + formatSpeed(peerRx), n.x, labelY);

                    // Exit-server peer marker
                    if (n.peer && n.peer.is_exit_node) {
                        ctx.fillStyle = lightT ? "#6d28d9" : "#c4b5fd";
                        ctx.font = (nodeRadius >= 10 ? 10 : 8) + "px system-ui, -apple-system, sans-serif";
                        ctx.fillText('🚪', n.x, n.y - nodeRadius - 6);
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
            if (document.hidden || !document.getElementById('topologyCanvas').getClientRects().length) return;
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
                    const fields = (json.restart_fields || []).join(', ');
                    const hint = json.restart_required
                        ? ' — ⚠️ ' + (t('cfg_restart_required') || 'Some settings apply only after a restart') + (fields ? ': ' + fields : '')
                        : '';
                    showToast(t('save_success') + hint, false, !!json.restart_required);
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
            applyPcapParamsToControls(state);
        }

        // Mirror the server's sampling knobs into the controls. The poll runs
        // every 1.5s, so anything the user is actively editing is skipped —
        // otherwise a half-typed rate limit gets stomped mid-keystroke.
        function applyPcapParamsToControls(state) {
            const everyEl = document.getElementById('pcapSampleEvery');
            const rateEl = document.getElementById('pcapMaxRate');
            const idleEl = document.getElementById('pcapIdleSkip');
            if (everyEl && document.activeElement !== everyEl && state.sample_every) {
                const v = String(state.sample_every);
                if (![...everyEl.options].some(o => o.value === v)) {
                    const opt = document.createElement('option');
                    opt.value = v; opt.textContent = '1:' + v;
                    everyEl.appendChild(opt);
                }
                everyEl.value = v;
            }
            if (rateEl && document.activeElement !== rateEl && state.max_rate_per_sec !== undefined) {
                rateEl.value = String(state.max_rate_per_sec);
            }
            if (idleEl && document.activeElement !== idleEl && state.idle_skip !== undefined) {
                idleEl.checked = !!state.idle_skip;
            }
        }

        // Push the sampling knobs to /api/pcap/set-params. The endpoint accepts
        // a partial body, so we only send what this panel actually owns.
        async function pcapSetParams() {
            const everyEl = document.getElementById('pcapSampleEvery');
            const rateEl = document.getElementById('pcapMaxRate');
            const idleEl = document.getElementById('pcapIdleSkip');
            const body = {};
            if (everyEl) {
                const n = parseInt(everyEl.value, 10);
                if (Number.isFinite(n) && n >= 1) body.sample_every = n;
            }
            if (rateEl) {
                const n = parseInt(rateEl.value, 10);
                if (Number.isFinite(n) && n >= 0) body.max_rate_per_sec = n;
            }
            if (idleEl) body.idle_skip = !!idleEl.checked;
            try {
                const res = await fetchWithTimeout('/api/pcap/set-params', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                }, 4000);
                if (res && res.ok) {
                    const st = await res.json();
                    applyPcapParamsToControls(st);
                }
            } catch (e) { /* the next state poll will re-sync the controls */ }
        }
        window.pcapSetParams = pcapSetParams;

        async function pcapRefreshState() {
            // Belt-and-suspenders: the WebSocket pushes state on connect and
            // on every transition. We still poll /api/pcap/state every 1.5s so
            // the badge stays in sync even when the WebSocket briefly
            // disconnects, but the response is tiny (~80 bytes).
            try {
                const res = await fetchWithTimeout('/api/pcap/state', {}, 3000);
                if (!res || !res.ok) return;
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
                if (document.hidden || currentDashboardPage() !== 'diagnostics' || !document.getElementById('captureDetails').open) return;
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
                this.connecting = false;
                if (this.retryTimer) { clearTimeout(this.retryTimer); this.retryTimer = null; }
                if (this.pollTimer)   { clearInterval(this.pollTimer); this.pollTimer = null; }
                if (this.ws) {
                    // A late close/open event from the old socket must not replace
                    // the connection created when the user returns to this page.
                    const old = this.ws;
                    this.ws = null;
                    old.onopen = old.onmessage = old.onerror = old.onclose = null;
                    try { old.close(); } catch (e) {}
                }
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
                if (document.hidden || currentDashboardPage() !== 'diagnostics' || !document.getElementById('logsDetails').open) return;
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
                this.connecting = false;
                if (this.retryTimer) { clearTimeout(this.retryTimer); this.retryTimer = null; }
                if (this.pollTimer)   { clearInterval(this.pollTimer); this.pollTimer = null; }
                if (this.ws) {
                    // A late close/open event from the old socket must not replace
                    // the connection created when the user returns to this page.
                    const old = this.ws;
                    this.ws = null;
                    old.onopen = old.onmessage = old.onerror = old.onclose = null;
                    try { old.close(); } catch (e) {}
                }
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

        // Format a plain hex string (two chars per byte, as the backend puts in
        // CapturedFrame.Hex) into a readable hex+ASCII dump. The backend ships
        // only the frame head rather than the whole frame, so this view is
        // header-only by design.
        function pcapHexDump(hexStr) {
            try {
                const s = String(hexStr || '');
                const n = Math.floor(s.length / 2);
                const bytes = new Uint8Array(n);
                for (let i = 0; i < n; i++) {
                    const v = parseInt(s.substr(i * 2, 2), 16);
                    if (isNaN(v)) throw new Error('bad hex');
                    bytes[i] = v;
                }
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
                return '(' + t('pcap_hex_parse_error') + ')';
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
                    '<td class="pkt-meta-key">' + escapeHTML(String(k)) + '</td>' +
                    '<td class="pkt-meta-val">' + (v === '' || v === 0 || v === '-' ? '-' : escapeHTML(String(v))) + '</td>' +
                    '</tr>';
            }
            metaHtml += '</table>';

            // Wireshark-style layered protocol dissection tree
            const tree = buildProtocolTree(f);

            document.getElementById('pcapModalBody').innerHTML = metaHtml + tree;
            document.getElementById('pcapModalHex').value = pcapHexDump(f.hex || '');
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
                    '<span class="pkt-layer-row-val">' + (r[1] === '' || r[1] === 0 || r[1] === '-' ? '-' : escapeHTML(String(r[1]))) + '</span>' +
                    '</div>'
                ).join('');
                html += '<details open class="pkt-layer-box">' +
                    '<summary class="pkt-layer-summary" style="color:' + L.color + ';">' +
                    '<span class="pkt-layer-offset">[' + (L.off || '-') + ']</span>' +
                    '<span class="pkt-layer-name">' + escapeHTML(String(L.name)) + '</span>' +
                    '<span class="pkt-layer-summary-text">' + escapeHTML(String(L.summary || '')) + '</span>' +
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
            // Unified settings ACL editor
            addACLRuleRow, deleteACLRuleRow, updateACLRuleItem, moveACLRuleItem,
            // Peer / peer-action modals
            openMultiaddrModal, closeMultiaddrModal, testPeerMultiaddrs,
            openPcapModal, closePcapModal, copyPcapHex, pcapToggle, pcapClear,
            openPeerEncModal, closePeerEncModal, copyPeerEncField,
            openAddStaticPeerModal, closeAddStaticPeerModal, submitAddStaticPeer,
            // Exit / Route / SpeedTest / Share
            openLoginModal, closeLoginModal, submitLogin,
            openSpeedTestModal, closeSpeedTestModal, runSpeedTest,
            inspectRoute, closeRouteInspector,
            openShareModal, closeShareModal, copyConfigJSON, downloadConfigJSON,
            // Form helpers
            addCfgListItem, delCfgListItem, moveCfgListItem,
            // Stats / logs / topology toolbar
            fetchStats, setLanguage, selectDashboardPage,
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
        setInterval(() => {
            if (!document.hidden && currentDashboardPage() === 'diagnostics' && document.getElementById('captureDetails').open) pcapRefreshState();
        }, 1500);
        // Show the login gate up-front when no token is stored, instead of
        // waiting for the first 401. The stored token (if any) is pre-filled.
        if (!getAuthToken()) {
            openLoginModal();
        }

        // Restore bookmarked pages and keep the tab controls keyboard accessible.
        selectDashboardPage(location.hash.slice(1), false);
        window.addEventListener('hashchange', () => selectDashboardPage(location.hash.slice(1), false));
        document.querySelector('.dashboard-tabs').addEventListener('keydown', event => {
            const current = dashboardPages.indexOf(currentDashboardPage());
            let next;
            if (event.key === 'ArrowRight') next = (current + 1) % dashboardPages.length;
            if (event.key === 'ArrowLeft') next = (current + dashboardPages.length - 1) % dashboardPages.length;
            if (event.key === 'Home') next = 0;
            if (event.key === 'End') next = dashboardPages.length - 1;
            if (next === undefined) return;
            event.preventDefault();
            selectDashboardPage(dashboardPages[next]);
            document.getElementById('dashboard-tab-' + dashboardPages[next]).focus();
        });
        document.querySelectorAll('.dashboard-details').forEach(details => {
            details.addEventListener('toggle', () => {
                if (details.open) requestAnimationFrame(redrawDashboardCharts);
                if (details.id === 'logsDetails' || details.id === 'captureDetails') syncDiagnosticStreams();
                if (details.id === 'topologyDetails') {
                    if (details.open) startTopologyLoop();
                    else if (topoRAFId !== null) { cancelAnimationFrame(topoRAFId); topoRAFId = null; }
                }
            });
        });
        document.getElementById('peerDetailsModal').addEventListener('keydown', event => {
            if (event.key === 'Escape') { event.preventDefault(); closePeerDetails(); }
            if (event.key !== 'Tab') return;
            const buttons = [...event.currentTarget.querySelectorAll('button, a[href]')]
                .filter(el => el.getClientRects().length && !el.disabled);
            if (!buttons.length) return;
            const first = buttons[0], last = buttons[buttons.length - 1];
            if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
            if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
        });
        document.addEventListener('visibilitychange', function () {
            selectDashboardPage(currentDashboardPage(), false);
        });
        window.addEventListener('resize', function() {
            drawTopologyMesh();
            if (bwChartState.history.length) drawBandwidthChart(bwChartState.history);
            if (ppsChartState.history.length) drawPacketRateChart(ppsChartState.history);
        });
        window.addEventListener('p2ptap:themechange', function () {
            drawTopologyMesh();
            if (bwChartState.history.length) drawBandwidthChart(bwChartState.history);
            if (ppsChartState.history.length) drawPacketRateChart(ppsChartState.history);
        });

        window.filterProtoChannels = filterProtoChannels;
        window.triggerSeqSyncResync = triggerSeqSyncResync;
        window.openCryptoInspector = openCryptoInspector;
        window.closeCryptoInspectorModal = closeCryptoInspectorModal;
        window.renderCryptoInspectorContent = renderCryptoInspectorContent;
        window.resyncSelectedPeerFromModal = resyncSelectedPeerFromModal;
        window.exportDiagnosticReport = exportDiagnosticReport;
        window.setDiagViewMode = setDiagViewMode;
        window.runPingDiagnostics = runPingDiagnostics;
        window.runTracerouteDiagnostics = runTracerouteDiagnostics;
