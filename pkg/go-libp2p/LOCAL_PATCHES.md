# 本地补丁清单（vendored go-libp2p）

本目录通过 `go.mod` 的 `replace github.com/libp2p/go-libp2p v0.50.0 => ./pkg/go-libp2p`
以源码形式参与构建。基线为上游 **v0.50.0**（2026-08-12 发布，当前最新版），
在此之上维护了以下 10 处本地补丁。升级到未来版本（v0.51+）时，需要把这份清单
中的补丁重新应用到新基线。

## 1. `p2p/host/basic/addrs_manager.go` — Android 接口地址提供者

- 新增包级钩子 `CustomInterfaceAddrsProvider func() ([]ma.Multiaddr, error)`；
  `updateUnlocked` 优先使用它获取接口地址，失败/为空时回退 `manet.InterfaceMultiaddrs()`。
- 用途：Android 上 netlink 受限，`pkg/android/android.go` 注入宿主 OS API 的地址列表。

## 2. `p2p/transport/tcp/tcp.go` — 监听 Control 钩子（`WithListenControl`）

- 新增 `ListenControlFn` 类型与 `WithListenControl(fn)` transport Option；
  TCP listener 创建时应用 `net.ListenConfig{Control: fn}`。
- 用途：`pkg/node/node.go` 传入 `listenerProtectControl`，把 TCP 监听 socket 绑定到
  物理网卡（SO_BINDTODEVICE / IP_BOUND_IF），防止 Exit Node 场景下回环进隧道。

## 3. `p2p/transport/webrtc/transport.go` + `listener.go` — 自定义 pion Net（`WithNet`）

- 新增 `WithNet(net pionnet.Net)` Option；SettingEngine.SetNet 应用到 ICE。
- 用途：`pkg/node/node.go` 传入 `NewProtectNet()`，WebRTC ICE 的 UDP socket 同样绑定
  物理网卡。

## 4. `p2p/protocol/holepunch/metrics.go` + `tracer.go` — 打洞超时指标

- 新增 Prometheus 计数器 `holepunch_timeouts_total`、`relay_timeouts_total`；
  tracer 在 `context.DeadlineExceeded` 时递增 direct 维度。

## 5. `p2p/transport/webrtc/transport.go` — SCTP 接收缓冲调优

- `sctpReceiveBufferSize` 从 `10 * maxReceiveMessageSize`（≈2.5MB）调大到
  `40 * maxReceiveMessageSize`（≈10MB，与 QUIC 的 MaxStreamReceiveWindow 对齐）。
- 依据（2026-09-06 基准实测，32 核 Windows 主机、1188B payload 饱和流）：
  2.5MB 窗口下发送端频繁停等，`BenchmarkThroughput_{TCP,UDP}/WebRTC` 丢帧
  30–70%；调到 10MB 后**丢帧归零**，有效吞吐从 ~1.9 MB/s 提升到 ~6.3 MB/s
  （约 3.3 倍）。上游默认 1MB（pion sctp `initialRecvBufSize`），libp2p 的
  10 消息注释基于消息级依赖场景，未考虑 VPN 饱和转发。
- 若未来向上游提 PR：这是一个独立的、带基准数据的性能补丁，适合单独提交。

## 6. `p2p/security/tls/crypto.go` + `p2p/transport/quic/transport.go` — QUIC ALPN `libp2p` → `h3`

- 把 TLS 身份 `alpn` 常量与 QUIC listener 的 `NextProtos` 从上游的 `"libp2p"` 改为
  `"h3"`（两处必须同步）。
- 动机（抗 DPI）：QUIC Initial 包只用**公开的 Initial salt** 加密，任何 DPI 都能解出
  ClientHello 里的 ALPN；一个 `"libp2p"` 字符串即可把流量归类为 libp2p。改 `"h3"` 后
  该字段与普通 HTTP/3 无从区分。
- 安全性：QUIC 的 muxer 走带内协商，**不依赖 ALPN 选 muxer**（`conn.ConnState()` 只带
  `Transport` 字段），故 ALPN 值纯外观。p2ptap 是与标准 libp2p 节点互通的私网，无需保留
  `"libp2p"`；混版（新↔旧）时 Go TLS ALPN 无交集只会协商为空协议、不致命，QUIC 握手照旧完成。

## 7. `p2p/security/tls/sni.go`（新文件）+ `crypto.go` + `transport.go` + `p2p/transport/quic/transport.go` — 统一 SNI

- 新增 `p2ptls.SetDialServerName(name)` / `DialServerName()`（RWMutex 守卫）；
  `Identity.ConfigForPeer` 末尾 `applyDialServerName(conf, remote)` —— 一处同时覆盖
  **TLS-over-TCP**（`SecureOutbound` 也从同一 Identity 取 client 配置）与 **QUIC**
  拨号，`transports.tls_server_name` 一份配置两路共用（对齐”TLS 和 QUIC 同一配置”的直觉）。
  ServerName 是 client-only 字段，误挂到 server 侧配置会被 crypto/tls 忽略，无害。
- **per-peer 派生模式**：`SetDialSNISuffix(s)` 启用后，`resolveDialServerName(remote)`
  把 SNI 计算为 `<peerSNILabel(remote)>.<s>`,label = 对端 PeerID 的
  `SHA-256("p2ptap-sni:"+peerID)` 前 16 位小写 hex（单条 DNS 安全标签）。同一 peer 稳定、
  不同 peer 唯一，避免”全网同一 SNI”的全局关联特征。suffix 优先于静态名；由
  `transports.tls_sni_suffix` 注入。回归测试 `sni_test.go::TestSniResolution` 锁
  优先级 + 唯一性 + 标签字符集。
- 入站观察（WebUI 显示用）：`ObserveInboundServerName`/`InboundServerNames`——TCP-TLS 的
  `SecureInbound` 与 QUIC listener 的 `GetConfigForClient` 都把对端 ClientHello 的
  server_name 按 remote host 记入带 TTL/上限的 map（连接洪泛不会变成内存 DoS）。节点
  按连接 remote IP 归属到 peer，WebUI 在”本机信息”显示自身出站 SNI、在”每对等加密”
  显示对端实际带来的 SNI，用于验证 `tls_server_name` 灰度是否到位。
- 动机：上游按 IP 拨号、ClientHello 不带 server_name,而真实 h3 客户端总带 SNI——
  “无 SNI”本身即特征。
- 安全性：libp2p 认证走证书内自签 peer 扩展（`InsecureSkipVerify` +
  `VerifyPeerCertificate`），**不校验 hostname**,SNI 纯外观、不削弱认证。
- 默认空 = 不带 SNI，保持上游行为与完全互通。

## 7b. 说明：QUIC-only 的旧写法已废弃

早期本补丁曾把 `SetDialServerName` 放在 `p2p/transport/quic` 包内、只在
`dialWithScope` 注入——那会让 TCP-TLS 拨号漏掉 SNI,与”TLS/QUIC 同一配置”的意图不符。
现统一收口到 `p2ptls.ConfigForPeer`,quic 侧不再持有 SNI 全局。

## 8. `p2p/transport/webrtc/stream_write.go` — 写超时下传到 SCTP

- `stream.SetWriteDeadline` 除写本地 `s.writeDeadline` 外，新增
  `s.dataChannel.SetWriteDeadline(t)`。
- 原因：本地 `writeDeadline` 只驱动 `Write()` 里 `availableSpace < minMessageSize`
  的等待分支；一旦 `s.writer.WriteMsg` 因发送缓冲占满而阻塞在 SCTP 层，代码根本不在
  `select` 里，本地超时永远不会触发。结果是一个满缓冲的 stream 会一直卡住，而同一条
  data channel 上的其他 stream（包括 FIN_ACK 控制消息）一并被拖住。读侧
  `stream_read.go` 是完整委托的，本补丁让写侧与读侧语义一致。

## 9. `p2p/transport/webrtc/udpmux/mux.go` — readLoop 死亡可观测

- `readLoop` 遇到非「已关闭」错误时，退出前调用 `mux.cancel()`；`Close()` 去掉
  `ctx.Done()` 短路，改为无条件 `cancel()` + `socket.Close()`。
- 原因：上游 `readLoop` 遇错只打一条 `log.Error` 就 return，mux 从此不再处理任何入站
  包，而 `Accept` 只在 `mux.queue` 和 `mux.ctx.Done()` 之间 select——于是 `Accept` 永久
  阻塞，入站 WebRTC 全部失效，唯一痕迹是那条日志。`Accept` 会拿到 `mux.ctx.Err()`，
  调用方才能丢掉监听器重开 socket。第二处修正：readLoop 已自行 cancel 时上游 `Close` 会
  提前 return 而不关 socket，泄漏监听 socket。

## 10. `p2p/transport/webrtc/transport.go` — `init()` 里的笔误

- `os.Executable()` → `os.Exit(1)`。上游原文写错了：`os.Executable()` 返回可执行文件路径
  后被丢弃，是一个空操作，multiaddr 组件注册失败时进程照旧继续启动。属上游遗留缺陷，
  本仓库顺带修掉（该分支实际不会触发）。

## 非代码附加目录

`examples/`、`test-plans/`、`scripts/test_analysis`（上游示例/测试计划的本地副本，不影响构建）。

## 与上游 diff 的方法

```bash
UP=$(go env GOMODCACHE)/github.com/libp2p/go-libp2p@v0.50.0
diff -rq "$UP" pkg/go-libp2p --exclude=".git"
```

预期结果：仅上列文件存在差异。升级基线后重新执行本 diff，确认补丁全部迁移且无遗漏。
