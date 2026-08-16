# p2ptap（中文）

基于 [go-libp2p](https://github.com/libp2p/go-libp2p) 构建的二层 P2P TAP VPN。把多个节点连成一张分布式的虚拟以太网交换机，无需中心服务器即可实现局域网互联、组播与 IPv4/IPv6 通信。

## 主要功能

- **二层虚拟交换机** — 完整的以太网帧转发、MAC 学习与广播/组播（ARP、mDNS、NDP）洪泛。
- **多传输协议** — QUIC、WebRTC Direct、WebTransport、TCP，可选 TCP Brutal 拥塞控制。
- **智能路由** — `best_path`（最低延迟）、`redundant`（双发零丢包）、`fallback`（自动故障转移）。
- **流量混淆** — 多种填充模式（`fixed`/`block`/`random`/`dynamic`/`auto`）抗 DPI 识别。
- **安全** — Ed25519 节点身份、Noise/TLS 1.3 加密、PSK 私有网络隔离、MAC 防伪造。
- **出口网关** — 允许其他节点通过指定的出口节点访问互联网（NAT 转发）。
- **内置 WebUI** — 实时仪表盘（测速、协议统计、网络诊断），支持 7 种语言。
- **OpenWrt LuCI 插件** — 原生 OpenWrt 集成，提供完整配置管理界面。
- **跨平台** — 支持 Linux、Windows、macOS 及 12 种 CPU 架构，单文件静态二进制。

## 快速开始

从 [Releases](https://github.com/NNdroid/p2ptap/releases) 下载，或从源码编译：

```bash
# 生成默认配置
p2ptap genconf -o config.json

# 运行
sudo ./p2ptap run -c config.json
```

WebUI 默认地址：`http://<tap_ip>`（如 `http://10.0.0.1`）。

更多配置与构建说明请参见 [英文 README](README.md)。

## 许可证

MIT — 详见 [LICENSE](LICENSE)。
