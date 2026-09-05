# 本地补丁清单（vendored go-libp2p）

本目录通过 `go.mod` 的 `replace github.com/libp2p/go-libp2p v0.49.0 => ./pkg/go-libp2p`
以源码形式参与构建。基线为上游 **v0.49.0**（2026-07-28 发布，当前最新版），
在此之上维护了以下 4 处本地补丁。升级到未来版本（v0.50+）时，需要把这份清单
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

## 非代码附加目录

`examples/`、`test-plans/`、`scripts/test_analysis`（上游示例/测试计划的本地副本，不影响构建）。

## 与上游 diff 的方法

```bash
UP=$(go env GOMODCACHE)/github.com/libp2p/go-libp2p@v0.49.0
diff -rq "$UP" pkg/go-libp2p --exclude=".git"
```

预期结果：仅上列文件存在差异。升级基线后重新执行本 diff，确认补丁全部迁移且无遗漏。
