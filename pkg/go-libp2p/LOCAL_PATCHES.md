# 本地补丁清单（vendored go-libp2p）

本目录通过 `go.mod` 的 `replace github.com/libp2p/go-libp2p v0.50.0 => ./pkg/go-libp2p`
以源码形式参与构建。基线为上游 **v0.50.0**（2026-08-12 发布，当前最新版），
在此之上维护了以下 **16 处**本地代码补丁。第 17 条是一段「已实现但回退」的
决策记录，供未来升级时参考，不是代码补丁。升级到未来版本（v0.51+）时，需要把
这份清单中的代码补丁重新应用到新基线。

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
- **勘误（见补丁 14）**：上面「混版不致命」的结论只适用于**上游 libp2p 的
  `quicreuse.NewConnManager`**。本项目把 QUIC 与 WebTransport 拆成两个 ConnManager 后，
  QUIC listener 的 `GetConfigForClient` 会对 hello 的 `SupportedProtos` 做**注册协议白名单**
  校验，遇到只广告 `"libp2p"` 的未升级对端会直接 `no supported protocol found` 拒绝，
  TLS 握手在那一步失败且**没有任何应用层日志**——部分升级时表现为「没升级的那些 peer
  的 QUIC 全部永久不通」。因此必须同时广告两个 ALPN（补丁 14）。

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

## 11. `p2p/transport/webrtc/transport.go` — ICE 服务器列表可热更新（`WithIceServers`）

- 抽出 `buildIceServers(stun, turn, username, credential)` 承载原有的
  「p2ptap 风格 URL → pion ICEServer」转换（STUN 支持 `/udp/host/port`、`stun:host:port`、
  裸 `host:port` 与补默认端口 19302，`/tcp/` 前缀一律跳过）；`New()` 里的静态分支改调它。
- 新增 `WithIceServers(stunServers, turnServers func() []string,
  turnCredentials func() (username, credential string))` 与 `iceServersProvider` 字段、
  `configWithIceServers()`：每次新建 PeerConnection 都重新解析一次列表。
  两个调用点（`newListener`、`newWebRTCConnection`）改用它。
- 原因：transport 在 `libp2p.New` 内部构造，早于 `Node` 存在，工厂闭包只能捕获构造期的
  配置快照——WebUI 改 STUN/TURN 列表后必须重启进程才生效。改为 provider 后，节点侧
  （`pkg/node/node.go`）把共享的 `atomic.Pointer[config.Config]` slot 传进来，热重载即生效。
  provider 非 nil 时**取代**静态三项（而非叠加），避免列表翻倍；nil 参数表示「没有该类服务器」，
  不会在握手中途 panic。
- 顺带把 `buildIceServers` 里「TURN 无凭据则丢弃」的日志从 `log.Error` 降为 `log.Debug`：
  provider 模式下每次握手都会调用一次，常驻错误配置会变成每条连接一条 Error。配置侧的
  一次性告警由 `pkg/node` 负责。
- 回归测试：`transport_ice_servers_test.go`（URL 转换表、provider 按连接重解析、基座配置
  不被污染、nil provider、provider 取代静态项）。

## 12. `p2p/net/swarm/swarm_dial.go` — 拨号取消不计入黑洞失败样本

- `dialAddr` 末尾原为 `s.bhd.RecordResult(addr, err == nil)`，即任何错误都记一次网络失败，
  取消也不例外。改为只按 `context.Cause(ctx)` 判定：`Cause == context.Canceled`（拨号被
  swarm 自己取消）不记录，其余照旧记录。
- 原因：同一 peer 的所有地址共用同一个 peer-dial ctx（`dial_worker.go` 中
  `addrDial.ctx = req.ctx`），一个地址胜出后 dial worker 返回、ctx 被收回，其余仍在飞的
  地址一律报「operation was canceled」。`swarm.NoDelayDialRanker` 让每个 peer 一轮同时发出
  全部地址（QUIC v4/v6、WebTransport v4/v6、WebRTC v4/v6 共 6 个 UDP），于是健康节点一轮
  就是 1 成功 + 5「失败」，成功率被压到约 15%；网格里只要混进几个 relay-only（对称 NAT、
  无 TURN）peer，一轮 6 失败 0 成功，100 条窗口约 15 轮后跌破默认 5% 阈值，`FilterAddrs`
  便剥掉**所有** peer 的**所有**公网 UDP 地址，`filterKnownUndialables` 返回
  `ErrDialRefusedBlackHole`，99/100 的拨号在真正开始之前就被拒。失败日志只是 Debug，
  整个过程在日志里完全看不到。
- 只查 Cause、不看 err 的原因：peer-dial 预算到期时，OS 会把被打断的 connect 同样报成
  `operation was canceled`，此时 `context.Cause` 才是 `deadline exceeded`。超时正是检测器
  本该收集的信号；若按 err 判定，超时会被一并吞掉，样本窗口永远为空、状态永远停在
  Probing，不可达地址再也不会被判定出来。
- p2ptap 侧配套：`pkg/node/node.go` 把 UDP 计数器设为 `MinSuccesses: 0`（永不 block——打洞与
  DCUtR 是到达对称 NAT peer 的唯一途径，且 relay 永远兜底，误 block 的代价只是浪费拨号时间
  而非丢连通性），IPv6 保留默认 5。本补丁让剩下的 IPv6 过滤保持真实语义。
- 回归测试：`black_hole_p2ptap_test.go`（`MinSuccesses=0` 永不 block；默认阈值确实会 block、
  且一次成功只回到 Probing 而非直接 Allowed）；上游 `TestBlackHoledAddrBlocked` 在
  Windows 上通过。

## 13. `p2p/transport/webrtc/listener.go` — mux 死亡向 listener 传播（消除僵尸监听）

- `listen()` 的 `l.mux.Accept(l.ctx)` 返回错误时，若 `l.ctx` 仍存活（说明是 mux 死了
  而不是我们主动取消），先 `l.mux.Close()` 释放 UDP socket，再 `l.cancel()`，然后才 return。
- 原因：`listener.ctx` 从 `context.Background()` 派生，**与 `mux.ctx` 没有父子关系**——
  mux 侧的死亡不会级联到 listener。上游在 mux 报错后只 `return`，于是 `listen()` 退出但
  `l.ctx` 永不取消：`Accept` 永久阻塞在 `l.ctx.Done()` 与空队列之间，swarm 永远等不到
  `ErrListenerClosed`，`AddrsFactory` 继续通告这个地址。而 mux 的 UDP socket 仍在
  读包、把 candidate 塞进一个永远没人消费的队列——**每个入站 STUN 都被静默丢弃**。
  症状是严格的单向不对称：出站 WebRTC 另开 socket 照旧可用，A 能连 B，B 连 A 永远超时，
  全链路只有 mux 那一条 Error 日志。补丁 9 让 mux 的 `Accept` 能返回错误，本补丁让这个
  错误真正生效。
- 为什么 cancel 不会误杀已建立连接：`l.ctx` 只用于 listener 自身的 accept 循环与
  `l.mux.Accept` 的等待，已建立的 PeerConnection/DTLS/SCTP 用的是各自独立的 ctx，
  因此这里最多是「停止接受新 candidate」，既不会切断现有连接，也不会影响出站拨号。

## 14. `p2p/transport/quic/transport.go` — QUIC ALPN 双广告（`h3` + `libp2p`）

- listener 的 `NextProtos` 由 `[]string{"h3"}` 改为 `[]string{"h3", "libp2p"}`，
  `"h3"` 仍排在第一位。
- 原因：本仓库把 QUIC 与 WebTransport 拆成两个独立的 `quicreuse.NewConnManager`
  （绕开两者在 connmgr 里按 ALPN 建键的冲突），QUIC 的 `GetConfigForClient` 于是只对
  QUIC 侧注册的协议做白名单校验。未升级的对端只广告 `"libp2p"`，白名单里没有 →
  `no supported protocol found` → TLS 握手失败，且 `quicreuse.Run()` 把这类错误直接
  return，`connmgr.go` 里 `go cl.Run()` 丢弃返回值，**全程无任何应用层日志**。结果是
  「只要没升级的那个 peer，QUIC 就永久不通」，一次部分升级就把整个 mesh 切半。
- 保留 `"h3"` 在首位：DPI 中性由**广告列表的第一个元素**决定（客户端 Initial 的
  ALPN 数组首个即 `"h3"`），所以抗 DPI 属性不变；追加 `"libp2p"` 只作兼容兜底。
- 为什么不影响 muxer 选择：QUIC 的 muxer 走带内协商，与 ALPN 无关；
  `p2p/security/tls/transport.go` 的 TCP-TLS 侧本来就把 `"h3"` 与 `"libp2p"` 都归一化为
  空协议名，不受影响。WebTransport 注册的是 `http3.NextProtoH3`（同样是 `"h3"`），
  但它有自己独立的 ConnManager，两边互不可见。

## 15. `p2p/transport/webrtc/udpmux/mux.go` — 接收缓冲 1500 → 65535

- `ReceiveBufSize` 常量从 1500 改为 65535（UDP 数据报上限）。
- 原因：`ReadFrom` 的目标缓冲小于实际数据报时，Go 会**静默截断**并把截断后的长度
  当作正常返回值，不报任何错误。pion 侧读 ICE candidate 用的是 8192 字节缓冲，
  所以截断发生在更上层的 socket 读——任何超过 1500 字节的包丢掉尾部字节且无任何
  上报，只在上游表现为卡死的 DTLS/SCTP 握手或偶发的 ICE 失败，完全没有诊断线索。
- 该值只用于接收缓冲，不参与写路径的发包大小决策（见常量上的上游注释），
  因此放大不会改变 path MTU 行为。

## 16. `p2p/protocol/holepunch/svc.go` — 曾尝试「无条件注册 handler」，已回退

- **当前状态：与上游 v0.50.0 一致，无本地改动。**
- 曾尝试的改动：在 `NewService` 里 `s.tracer.Start()` 之后立刻
  `s.host.SetStreamHandler(Protocol, s.handleNewStream)`，让没有公网地址的节点
  也能作为 DCUtR 的响应方。
- **回退原因（已实测）**：该改动稳定破坏上游 `p2p/protocol/holepunch` 的
  `TestDirectDialWorks`、`TestEndToEndSimConnect`（legacy=true/false 两个子用例）
  与 `TestEndToEndSimConnectQUICReuse` —— 全部表现为
  `failed to dial ... all dials failed * [/ip4/2.2.0.2/udp/8001/quic-v1] timeout:
  no recent network activity`（5.02s 超时）。用 `git worktree` 建 HEAD 干净基线
  逐个补丁二分确认：仅此一处改动即可稳定复现（连续 3 次），
  补丁 13/14/17 单独都不影响。回退后这三个用例 6.02s 全绿。
- **为什么功能上也不值得保留**：`incomingHolePunch` 自己会读 `s.listenAddrs()`，
  为空时返回 `rejecting hole punch request, as we don't have any public addresses`
  —— 提前注册 handler 并不会让无公网地址的节点真正可被打洞，它仍然会正确拒绝。
  该改动唯一实质收益是 `DirectConnect` 不会永久阻塞在 `hasPublicAddrsChan` 上
  （该 channel 只在 `waitForPublicAddr` 成功后才 close），而 p2ptap 从不调用
  `DirectConnect`（见 `pkg/node/node.go` 只用了 `EnableHolePunching`）。
- **升级提示**：p2ptap 节点启动初期、或全部 STUN/observed 地址尚未发现时，
  `HolePunchAddrs()` 为空，该节点此时不能被当作打洞目标。这是上游既有设计，
  且与「无公网映射地址就无法被打洞」这一物理事实一致，不是本仓库需要修的缺陷。

## 17. `p2p/transport/quicreuse/listener.go` — 拒绝挂载到死 listener + accept 失败告警

- `Add()` 开头检查 `l.running` 是否已关闭，已关闭则返回
  `quic listener on <addr> is closed`，而不是构造一个新的 `listener` 挂上去。
- `Run()` 在遇到非「已关闭」错误时打一条 Error 日志，再 return。
- 原因：`quicListener.Run()` 一旦因错误退出，`l.running` channel 被 close，但
  `refCount` 仍大于 0，因此该 listener 在 `connManager` 表里**永远不会被清理**。
  下一次 `Add()` 复用它时，新 `listener` 的 `acceptLoopRunning` 就是这条已关闭的
  channel，于是每个 `Accept` 立刻返回，该地址在整个进程生命周期内不可达，
  而调用方拿不到任何错误（`Accept` 返回 `ErrListenerClosed` 但地址仍被通告）。
  在 `Add` 阶段直接失败，才能把坏地址从通告列表里剔除而不是带着它上线。
- 第二处：上游 `Run()` 直接 `return err`，而 `connmgr.go` 的
  `go cl.Run()` 丢弃返回值，listener 死了没人知道。日志里看不到这一点时，
  故障只能表现为「某个地址的 QUIC 突然全部不通」，且没有对应日志可查。
- 注：`log` 是包级变量 `var log = gologshim.Logger("quicreuse")`（定义在 `connmgr.go`），
  本补丁无需新增 import。

## 非代码附加目录


`examples/`、`test-plans/`、`scripts/test_analysis`（上游示例/测试计划的本地副本，不影响构建）。

## 与上游 diff 的方法

```bash
UP=$(go env GOMODCACHE)/github.com/libp2p/go-libp2p@v0.50.0
diff -rq "$UP" pkg/go-libp2p --exclude=".git"
```

预期结果：仅上列文件存在差异。升级基线后重新执行本 diff，确认补丁全部迁移且无遗漏。
