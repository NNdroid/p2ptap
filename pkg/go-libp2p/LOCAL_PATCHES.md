# 本地补丁清单（vendored go-libp2p）

本目录通过 `go.mod` 的 `replace github.com/libp2p/go-libp2p v0.50.0 => ./pkg/go-libp2p`
以源码形式参与构建。基线为上游 **v0.50.0**（2026-08-12 发布，当前最新版），
在此之上维护了 **17 处**本地代码补丁（第 1–5、7、8–13、15、17–20 条）。

第 **6**、**14**、**16** 条是「已实现但回退」的决策记录：代码已恢复上游原样，
条目本身保留，说明**为什么不能这样改**——这三处都曾以「抗 DPI」或「提升可达性」
为名落地，最后都演变成某个协议彻底不可达，重读条目可以避免重蹈覆辙。
升级到未来版本（v0.51+）时，只需重新应用真正存在的代码补丁。

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
  的 QUIC 全部永久不通」。因此当时改为同时广告两个 ALPN（补丁 14）。

- **撤回（2026-10，见补丁 14）**：上面这条「必须双广告」的结论同样是错的，它假设
  QUIC 与 WebTransport 各持一个 ConnManager、两个 listener 互不可见。一旦两者共享
  同一个 `quicreuse.ConnManager`（上游默认做法，本项目也已如此，见
  `pkg/node/transport_options.go`），两个 listener 就合并成一个，`h3` 必然冲突，
  其中一个协议直接消失。现已改回上游的 `"libp2p"`。混版互通问题也随之消失——
  未升级对端本就广告 `"libp2p"`。

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

## 14. `p2p/transport/quic/transport.go` — 曾「QUIC ALPN 双广告（`h3` + `libp2p`）」，已回退

- 原补丁把 listener 的 `NextProtos` 由 `[]string{"h3"}` 改为
  `[]string{"h3", "libp2p"}`，`"h3"` 仍排首位（抗 DPI 由首元素决定），
  `"libp2p"` 只作兼容兜底。**现已恢复上游的 `[]string{"libp2p"}`。**

- 为什么要撤回：`quicreuse` 按 ALPN 做**连接复用与分流**，一个
  `quicreuse.Listener` 上每个 ALPN 只能被注册一次（`listener.go` 的
  `Add()` 对已注册协议直接 `already listening for protocol h3` 报错）。
  WebTransport 的 ALPN 是 `"h3"`，**不可更改**（HTTP/3 协议强制）。于是：
  - QUIC 与 WebTransport 共享同一个 ConnManager 时（上游默认，本项目亦如此），
    两者落在同一个 listener 上，后注册的那个直接失败，**整个协议从这个地址上消失**；
  - 更糟的是失败发生在 `Add()` 内部，`Transport.Listen` 拿到错误后该地址
    仍可能出现在通告列表里，表现就是「对端看得到地址，但连不上」，且无任何日志。
  这不是概率性劣化，而是配置了 QUIC+WebTransport 同端口时 100% 掉一个协议。

- 为什么没有折中方案：想保留抗 DPI，就必须让 QUIC 广告一个非 `"libp2p"` 的
  ALPN；而 QUIC 与 WebTransport 只要共享 socket，ALPN 就**必须互不相交**。
  WebTransport 占了 `"h3"`，QUIC 就只剩 `"libp2p"`（或任何其他字符串，但那样
  既不被上游接受，也没有抗 DPI 意义）。两条路互斥，本项目选择可达性。

- 混版互通同样不再有问题：未升级对端广告的正是 `"libp2p"`，与本项目一致。
  补丁 6 里为了解决「未升级对端被拒」而引入的双广告，其前提（两个独立
  ConnManager）在本项目里已经不成立，因此那个问题不复存在。

- 副作用（如实记录）：**丢失 QUIC 流量的 ALPN 级抗 DPI**。QUIC Initial 用公开
  salt 加密，DPI 仍可读出 `"libp2p"`。补丁 7 的 SNI 伪装仍然生效，是唯一保留的
  抗 DPI 手段。若要恢复抗 DPI，只能让 QUIC 独占端口、WebTransport 另起端口，
  并接受两者无法共用一个 UDP 端口的限制。

- 回归测试：`pkg/node/transport_options_test.go` 的
  `TestSharedQUICReuseSharesAPortBetweenQUICAndWebTransport`（含 reuseport 开/关两种
  子用例）锁住「同端口上 QUIC 与 WebTransport 同时可监听、可同时拨通」，
  谁再把 ALPN 改成含 `"h3"` 就会在这里失败。

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

## 18. `p2p/host/basic/addrs_manager.go` — HolePunchAddrs 必须带 certhash

- `HolePunchAddrs()` 由 `slices.Clone(a.addrsFactory(addrs))` 改为
  `a.applyAddrsFactory(addrs)`。
- 原因：`addrsFactory` 的输出是这份列表里**唯一**绕过 `getLocalAddrs` 的部分，
  而 certhash 正是在 `getLocalAddrs` 里经 `addCertHashes` 挂上的。`DirectAddrs()`
  与 `observedAddrsManager.Addrs(1)` 都已经带 hash，只有工厂新造的地址（NAT 映射
  端点、relay 端点）是裸的。
- 为什么这是真缺陷：DCUtR 打洞时会把 `HolePunchAddrs()` 整体经 `/libp2p/dcutr`
  发给对端，对端拿到的地址会**原样拨号**。而
  `webRTCTransport.CanDial` 与 `IsWebtransportMultiaddr` 都要求 certhash 数 ≥ 1，
  裸 `/webrtc-direct/`、`/webtransport/` 地址会被直接拒绝——于是打洞时
  WebRTC/WebTransport 这一条腿静默丢失，QUIC/TCP/WS 照旧成功。表现是「同一个
  对端有时打得通有时打不通」，且只在地址恰由工厂产生时才触发，所以很难归因。
- 注意区分：上游 `HolePunchAddrs` 对**自己的**监听地址其实没问题（那些地址
  已经过 `getLocalAddrs`）。真正的缺口只在工厂新增的地址上。当前 p2ptap 的
  `AddrsFactory` 只注入 `/udp/<port>/quic-v1`，而本 fork 的 QUIC 不使用 certhash，
  所以这个补丁目前更多是**封堵隐患**：一旦将来让工厂也注入 WebRTC/WebTransport
  端点（例如给 WebRTC-only 对端提供 TURN 回退地址），不加这一行那批地址一定拨不通。
- 回归用例：`p2p/host/basic/addrs_manager_test.go` 的
  `TestHolePunchAddrsCarryCertHashes`——它让 `AddrsFactory` 额外注入一个只有工厂
  知道的裸 `/webrtc-direct/` 端点，断言输出里每个 `webrtc-direct` 地址都带 hash。
  本补丁前该用例失败、加回原始写法后立刻失败（两个方向都验证过）。

## 19. `gologshim/gologshim.go` — 默认日志级别 Error → Warn

- `parseIPFSGoLogEnv` 的空环境变量回退值由 `slog.LevelError` 改为 `slog.LevelWarn`。
- 原因：libp2p 不用 `slog.Default()`，各包用自己的 `gologshim.Logger(system)`，
  其级别只认 `GOLOG_LOG_LEVEL`，未设置时回退到 **Error**。于是 libp2p 发出的
  **每一条 Warn 都被静默丢弃**。
- 最严重的受害者是 `p2p/net/swarm/swarm_listen.go` 的
  `log.Warn("listening failed", ...)`：当一个 transport 已注册但地址绑定失败
  （如端口占用、协议层叠错误被校验漏掉）时，这是**唯一**的征兆，而
  `swarm.Listen` 只在「全部地址都失败」时才返回 error，部分失败对调用方完全不可见。
  实际事故：`p2ptap-boot` 早期版本只注册了 QUIC + WebRTC 两个 transport，
  `/tcp/` 与 `/quic-v1/webtransport/` 两个监听地址从头到尾没有监听器，
  进程整个生命周期内一条 "listening failed" 都没有出现在 journalctl 里，
  故障只能靠外部端口扫描发现。
- 为什么不是把该处 Warn 改成 Error：全仓有 97 处非测试 Warn 调用点（GC 失败、
  地址解析失败、慢消费者等），都是真运维告警，只是被同一道闸门一并吞掉。
  这里改默认级别是根因修复；逐点升级会在下次上游新增 Warn 时复发。
- 兼容性：`GOLOG_LOG_LEVEL` 显式设置时仍然优先生效（包括 `swarm2=debug` 这类
  按系统细分的写法），本补丁只改变「未设置时」的行为。日志目标仍是 `os.Stderr`，
  格式不变，因此 systemd journal / 容器日志无需任何调整。
- 与第 17 条的关系：第 17 条把 `quicreuse` 的 accept 失败从上游的静默 `return err`
  升级为一条日志，并**故意选 Error 级别**以保证在默认级别下可见——正因为这道闸门
  存在。本补丁落地后，那条 Error 依旧可见，语义不变。
- 上游测试改动：`gologshim/gologshim_test.go` 的
  `TestParseIPFSGoLogEnv/empty_string_uses_default_level` 把期望值从
  `slog.LevelError` 改为 `slog.LevelWarn`——该用例正是把上游默认级别钉死的断言，
  不跟着改必失败。其余三个子用例都显式传入级别字符串，不受影响。

## 20. `p2p/transport/quicreuse/config.go` — QUIC 流控窗口按 VPN 场景放大

- `InitialStreamReceiveWindow` 512KB（quic-go 默认，上游未设）→ **1MB**；
  `MaxStreamReceiveWindow` 10MB → **32MB**；
  `InitialConnectionReceiveWindow` → **4MB**；
  `MaxConnectionReceiveWindow` 15MB → **64MB**。
- 原因：流控窗口是单流的**硬性吞吐上限**——在途字节不可能超过窗口，所以单流上限 =
  窗口 / RTT。上游默认值面向请求/响应流量，6–10MB 的流窗口在 100ms 链路上只允许
  ~490–800 Mbps，200ms 掉到 250–400 Mbps；初始 512KB 更让每次大流量传输的头几百毫秒
  都在慢启动窗口里爬。p2ptap 是 VPN，单条流就是一次大文件传输，窗口直接决定用户看到的速度。
- 不占内存：这些值是**信用额度**而非预分配缓冲，quic-go 只为真实在途的载荷分配内存。
  32MB/64MB 的取值按「覆盖 200ms RTT 下 1.28 Gbps」留足余量，实际在途量受 BDP 限制，
  手机上通常只有几百 KB。
- 生效范围：`quicreuse` 是所有 QUIC 与 WebTransport 连接的公共出口
  （`ConnManager.clientConfig` 与 `newQuicListener` 都 clone 这份配置），因此 QUIC、
  WebTransport 两条腿同时受益，无需逐 transport 接线。**对端也要跑这个版本**——
  接收窗口由连接两端各自声明，只改一端时提升的是对方发给你的方向。
- 不新增配置项：窗口由链路 BDP 决定，与用户场景无关，做成运行时开关只会制造
  「调错了更慢」的可能。将来要调就改这里一处。

## 非代码附加目录


`examples/`、`test-plans/`、`scripts/test_analysis`（上游示例/测试计划的本地副本，不影响构建）。

## 与上游 diff 的方法

```bash
UP=$(go env GOMODCACHE)/github.com/libp2p/go-libp2p@v0.50.0
diff -rq "$UP" pkg/go-libp2p --exclude=".git"
```

预期结果：仅上列文件存在差异。升级基线后重新执行本 diff，确认补丁全部迁移且无遗漏。

## 修改本目录前必须本地跑上游测试

本目录是嵌套 module（有自己的 `go.mod`），`go test ./...` 在主仓**不会**进入这里，
上游测试也**刻意不纳入 CI**。这曾经是实际坑：一处 `p2p/protocol/holepunch/svc.go`
补丁通过了主仓全部测试与 CI，却稳定破坏 3 个上游用例（`TestDirectDialWorks`、
`TestEndToEndSimConnect` 两个子用例、`TestEndToEndSimConnectQUICReuse`），
直到本地显式运行 fork 测试才被发现。

改动本目录任何文件后，推送前必须本地执行：

```bash
cd pkg/go-libp2p
go build ./...
go vet ./p2p/transport/... ./p2p/protocol/... ./p2p/security/... ./p2p/net/...
go test ./p2p/transport/... ./p2p/protocol/... ./p2p/security/... ./p2p/net/... -count=1
```

其中 `p2p/net/swarm` 约 40s、`p2p/transport/webrtc` 约 12s、`protocol/holepunch` 约 6s。
