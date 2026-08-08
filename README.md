# p2ptap

[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8.svg)](https://golang.org)
[![libp2p](https://img.shields.io/badge/libp2p-v0.41+-3572A5.svg)](https://libp2p.io)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-19.07~24.10+-0088cc.svg)](https://openwrt.org)

A Layer-2 P2P TAP VPN built on [go-libp2p](https://github.com/libp2p/go-libp2p). Turns your nodes into a distributed virtual Ethernet switch over encrypted P2P tunnels — LAN gaming, multicast, and IPv4/IPv6 networking without a central server.

## Features

- **Layer-2 Virtual Switch** — Full Ethernet frame forwarding, MAC learning, and broadcast/multicast (ARP, mDNS, NDP) flooding.
- **Multi-Transport** — QUIC, WebRTC Direct, WebTransport, TCP with optional [TCP Brutal](https://github.com/apernet/tcp-brutal) congestion control.
- **Smart Routing** — `best_path` (lowest RTT), `redundant` (dual-send for zero packet loss), or `fallback` (auto failover).
- **Traffic Obfuscation** — Padding modes (`fixed`, `block`, `random`, `dynamic`, `auto`) with jitter for anti-DPI.
- **Security** — Ed25519 node identity, Noise/TLS 1.3 encryption, PSK private network isolation, MAC anti-spoofing.
- **Exit Gateway** — Allow peers to access the internet through a designated exit node with NAT masquerade.
- **Built-in WebUI** — Real-time dashboard with speedometer, protocol stats, and network diagnostics. 7-language i18n.
- **OpenWrt LuCI App** — Native OpenWrt integration with full-configuration web admin panel. 4-language i18n.
- **Cross-Platform** — Linux, Windows, macOS. 12 CPU architectures.
- **Zero Dependencies** — Single static binary.

## Quick Start

Download from [Releases](https://github.com/NNdroid/p2ptap/releases) or build from source.

### Linux (systemd)

```bash
sudo ./scripts/install-p2ptap.sh install      # Install as systemd service
sudo ./scripts/install-p2ptap-boot.sh install  # Install bootstrap server
```

### Manual

```bash
sudo ./p2ptap run -c config.json
# WebUI → http://10.0.0.1
```

### OpenWrt

```bash
# opkg (19.07 ~ 23.05)
opkg install p2ptap_*.ipk luci-app-p2ptap_*.ipk

# apk (24.10+)
apk add --allow-untrusted p2ptap_*.apk luci-app-p2ptap_*.apk
```

Access: **Services → P2P TAP VPN** in LuCI.

## Configuration

```json
{
  "listen_addrs": ["/ip4/0.0.0.0/udp/4001/quic-v1"],
  "bootstrap_peers": [],
  "static_peers": [],
  "enable_mdns": true,
  "node_name": "auto",
  "tap_name": "p2ptap0",
  "tap_ip": "10.0.0.1/24",
  "tap_ipv6": "fd00::1/64",
  "tap_mac": "02:00:00:00:00:01",
  "psk": "",
  "transport_strategy": "best_path",
  "transports": {
    "enable_quic_reuse": true,
    "enable_webrtc": true,
    "enable_webtransport": true,
    "enable_tcp_reuse": true,
    "enable_tcp_brutal": false,
    "tcp_brutal_rate": "100Mbps"
  },
  "obfuscation": {
    "enable": true,
    "mode": "fixed",
    "fixed_size": 1500,
    "block_size": 256
  },
  "web_ui": {
    "enable": true,
    "listen_ip": "10.0.0.1",
    "listen_ipv6": "fd00::1",
    "port": 80
  }
}
```

Generate default config: `p2ptap genconf -o config.json`

## Bootstrap Server

Run a lightweight DHT hub + Circuit Relay on any public VPS:

```bash
./p2ptap-boot -port 4001 -key boot.key
```

Copy the printed multiaddr into your nodes' `bootstrap_peers`.

## Build

```bash
# All architectures
./scripts/build.sh

# Or manually
go build ./cmd/p2ptap
go build ./cmd/p2ptap-boot
```

Output in `./bin/`: standalone archives + OpenWrt packages across 12 architectures.

## Test

```bash
go test -v ./...
```

## License

MIT — see [LICENSE](LICENSE).
