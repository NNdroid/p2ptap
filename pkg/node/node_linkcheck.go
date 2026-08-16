package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"p2ptap/pkg/observer"
)

// DiagnoseLink performs a deep, 7-stage transport-layer link check on a single
// multiaddr:
//
//	1 multiaddr valid (parse)        5 Noise / TLS handshake
//	2 DNS resolves                   6 Peer ID matches expected
//	3 TCP / QUIC socket established  7 libp2p connection success
//	4 libp2p transport success
//
// It returns nil only if the node has not wired the collector callback; on any
// input it always returns a populated LinkDiagnosis so the WebUI can render the
// step-by-step verdict.
func (n *Node) DiagnoseLink(multiaddrStr string) *observer.LinkDiagnosis {
	diag := &observer.LinkDiagnosis{Input: multiaddrStr}

	addStep := func(idx int, key, detail string, passed, skipped bool, d time.Duration) {
		diag.Steps = append(diag.Steps, observer.LinkStep{
			Index:      idx,
			Key:        key,
			Passed:     passed,
			Skipped:    skipped,
			Detail:     detail,
			DurationMs: d.Milliseconds(),
		})
	}
	finish := func() *observer.LinkDiagnosis {
		finalizeLinkOverall(diag)
		return diag
	}

	// ---- Stage 1: multiaddr syntactically valid ----
	t0 := time.Now()
	maAddr, err := ma.NewMultiaddr(multiaddrStr)
	dt := time.Since(t0)
	if err != nil {
		addStep(1, "multiaddr_valid", "multiaddr 语法非法: "+err.Error(), false, false, dt)
		return finish()
	}
	addStep(1, "multiaddr_valid", "multiaddr 解析成功", true, false, dt)

	// peer id carried in /p2p/<id>, if any
	pid, _ := peer.IDFromP2PAddr(maAddr)
	if pid != "" {
		diag.TargetPeer = pid.String()
	}

	// transport detection (for the raw socket probe hint)
	switch {
	case strings.Contains(multiaddrStr, "quic"):
		diag.Transport = "quic-v1"
	case strings.Contains(multiaddrStr, "ws"):
		diag.Transport = "websocket"
	case strings.Contains(multiaddrStr, "tcp"):
		diag.Transport = "tcp"
	default:
		diag.Transport = "unknown"
	}

	// ---- Stage 2: DNS resolves ----
	t0 = time.Now()
	resolvedIPs, dnsErr := lookupDNSMultiaddr(maAddr)
	dt = time.Since(t0)
	diag.ResolvedIPs = resolvedIPs
	if hasDNSComponent(maAddr) {
		if dnsErr != nil {
			addStep(2, "dns_resolve", "DNS 解析失败: "+dnsErr.Error(), false, false, dt)
			return finish()
		}
		detail := "DNS 解析成功"
		if len(resolvedIPs) > 0 {
			detail += ": " + strings.Join(resolvedIPs, ", ")
		}
		addStep(2, "dns_resolve", detail, true, false, dt)
	} else {
		addStep(2, "dns_resolve", "静态 IP 地址，无需 DNS 解析", true, true, dt)
	}

	// Candidates to dial: libp2p (and the raw-socket probe) resolve /dns* components
	// internally, so we keep the original multiaddr (with its DNS component) as-is
	// rather than expanding it by hand.
	candidates := []ma.Multiaddr{maAddr}

	// transport-only variants (strip /p2p/<id>) for raw socket + libp2p dial
	peerAddrs := make([]ma.Multiaddr, 0, len(candidates))
	for _, c := range candidates {
		if stripped := stripP2P(c); stripped != nil {
			peerAddrs = append(peerAddrs, stripped)
		}
	}
	if len(peerAddrs) == 0 {
		peerAddrs = candidates
	}

	// ---- Stage 3: raw TCP / QUIC socket establishment ----
	t0 = time.Now()
	rawOK, rawFatal, rawDetail := probeRawTransport(peerAddrs)
	dt = time.Since(t0)
	addStep(3, "tcp_quic_established", rawDetail, rawOK, false, dt)
	if !rawOK && rawFatal {
		// Transport socket is hard-down (e.g. connection refused / timeout on TCP).
		// libp2p connect in stage 4 will surface the same failure with detail.
		diag.Summary = "传输层套接字不可达（TCP 连接被拒或超时）"
	}

	// ---- Stages 4-7: libp2p transport → handshake → peer-id → connection ----
	if pid == "" {
		for _, s := range []struct {
			i   int
			key string
		}{
			{4, "libp2p_transport"},
			{5, "noise_tls_handshake"},
			{6, "peer_id_match"},
			{7, "libp2p_connection"},
		} {
			addStep(s.i, s.key, "地址未包含 /p2p/<PeerID>，无法执行 libp2p 连接检测（请提供含 /p2p/ 的完整 P2P multiaddr）", false, true, 0)
		}
		return finish()
	}

	ctx, cancel := context.WithTimeout(n.ctx, 12*time.Second)
	defer cancel()

	n.Host.Peerstore().AddAddrs(pid, peerAddrs, peerstore.TempAddrTTL)
	t0 = time.Now()
	connErr := n.Host.Connect(ctx, peer.AddrInfo{ID: pid, Addrs: peerAddrs})
	dt = time.Since(t0)

	s4, s5, s6, s7 := false, false, false, false
	d4, d5, d6, d7 := "", "", "", ""
	if connErr == nil {
		s4, s5, s7 = true, true, true
		d4 = "libp2p 传输层连接建立成功"
		d5 = "Noise / TLS 握手成功"
		if conns := n.Host.Network().ConnsToPeer(pid); len(conns) > 0 {
			actual := conns[0].RemotePeer()
			if actual == pid {
				s6 = true
				d6 = "对端 Peer ID 与预期一致: " + pid.String()
			} else {
				s6 = false
				d6 = "Peer ID 不匹配！预期 " + pid.String() + " 实得 " + actual.String()
			}
		} else {
			s6 = true
			d6 = "握手已完成（连接已建立）"
		}
		d7 = "libp2p 连接成功"
	} else {
		transportFail, securityFail, peerIDFail, msg := classifyConnErr(connErr)
		switch {
		case transportFail:
			d4 = "传输层连接失败: " + msg
			d5, d6, d7 = "未到达（传输层失败）", "未到达（传输层失败）", "未到达（传输层失败）"
		case securityFail:
			s4 = true
			d4 = "libp2p 传输层连接建立成功"
			d5 = "Noise / TLS 握手失败: " + msg
			d6, d7 = "未到达（握手失败）", "未到达（握手失败）"
		case peerIDFail:
			s4, s5 = true, true
			d4 = "libp2p 传输层连接建立成功"
			d5 = "Noise / TLS 握手成功"
			d6 = "Peer ID 不匹配: " + msg
			d7 = "未到达（Peer ID 不匹配）"
		default:
			d4 = "连接失败: " + msg
			d5, d6, d7 = "未到达", "未到达", "未到达"
		}
	}
	addStep(4, "libp2p_transport", d4, s4, false, dt)
	addStep(5, "noise_tls_handshake", d5, s5, false, dt)
	addStep(6, "peer_id_match", d6, s6, false, dt)
	addStep(7, "libp2p_connection", d7, s7, false, dt)

	return finish()
}

// probeRawTransport attempts a raw socket connection to the first viable
// transport address. For TCP it is authoritative; for UDP/QUIC the OS "connect"
// performs no handshake, so a failure there is informational (rawFatal=false)
// and the real QUIC establishment is decided by the libp2p transport in stage 4.
func probeRawTransport(addrs []ma.Multiaddr) (ok, fatal bool, detail string) {
	for _, a := range addrs {
		netType, dialAddr, err := manet.DialArgs(a)
		if err != nil {
			if clean, e := extractCleanTransportMA(a); e == nil {
				netType, dialAddr, err = manet.DialArgs(clean)
			}
			if err != nil {
				continue
			}
		}
		switch {
		case strings.HasPrefix(netType, "tcp"):
			conn, derr := net.DialTimeout(netType, dialAddr, 4*time.Second)
			if derr != nil {
				return false, true, "TCP 套接字连接失败 (" + netType + " " + dialAddr + "): " + derr.Error()
			}
			conn.Close()
			return true, false, "TCP 套接字已建立 (" + dialAddr + ")"
		case strings.HasPrefix(netType, "udp"):
			conn, derr := net.DialTimeout(netType, dialAddr, 4*time.Second)
			if derr != nil {
				// UDP connect performs no handshake; a failure here only means the
				// endpoint is unreachable at the socket layer. Still report, but do
				// not treat it as fatal — stage 4 is the authoritative QUIC check.
				return false, false, "UDP 套接字不可达 (" + dialAddr + ")，QUIC 握手将在步骤4验证: " + derr.Error()
			}
			conn.Close()
			return true, false, "UDP 套接字可达（QUIC 握手见步骤4）: " + dialAddr
		default:
			return true, false, "识别到传输层端点 (" + netType + " " + dialAddr + ")"
		}
	}
	return false, false, "无法从地址中提取可探测的传输层端点"
}

// lookupDNSMultiaddr resolves the DNS component of a multiaddr (if any) to its
// IP addresses using the standard resolver. libp2p itself resolves /dns* at dial
// time, so we only resolve here to (a) decide whether stage 2 passes and
// (b) surface the concrete IPs in the diagnosis. Returns (resolvedIPs, err);
// err is nil (and resolvedIPs empty) when the multiaddr has no DNS component.
func lookupDNSMultiaddr(m ma.Multiaddr) ([]string, error) {
	host := dnsHost(m)
	if host == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if ip := a.IP.String(); ip != "" {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses for %q", host)
	}
	return ips, nil
}

// dnsHost returns the hostname embedded in a /dns, /dns4, /dns6 or /dnsaddr
// component, or "" when the multiaddr is purely IP-based.
func dnsHost(m ma.Multiaddr) string {
	for _, code := range []int{ma.P_DNS4, ma.P_DNS6, ma.P_DNS, ma.P_DNSADDR} {
		if v, err := m.ValueForProtocol(code); err == nil && v != "" {
			return v
		}
	}
	return ""
}

func hasDNSComponent(m ma.Multiaddr) bool {
	return dnsHost(m) != ""
}

func stripP2P(m ma.Multiaddr) ma.Multiaddr {
	if _, err := m.ValueForProtocol(ma.P_P2P); err == nil {
		rest, e := ma.SplitLast(m)
		if e == nil {
			return rest
		}
	}
	return m
}

// classifyConnErr maps a libp2p dial error onto the layer where the failure
// occurred: transport (TCP/QUIC socket), security (Noise/TLS handshake) or
// peer-id mismatch. Priority is peer-id > security > transport.
func classifyConnErr(err error) (transport, security, peerID bool, msg string) {
	msg = err.Error()
	all := collectErrStrings(err)
	hasPeer, hasSec, hasTrans := false, false, false
	for _, s := range all {
		ls := strings.ToLower(s)
		if strings.Contains(ls, "peer id") || strings.Contains(ls, "does not match") ||
			(strings.Contains(ls, "expected") && strings.Contains(ls, "peer")) {
			hasPeer = true
		}
		if strings.Contains(ls, "handshake") || strings.Contains(ls, "noise") ||
			strings.Contains(ls, "tls") || strings.Contains(ls, "cryptographic") ||
			strings.Contains(ls, "x509") || strings.Contains(ls, "certificate") ||
			strings.Contains(ls, "signature") || strings.Contains(ls, "secretbox") ||
			strings.Contains(ls, "decrypt") {
			hasSec = true
		}
		if strings.Contains(ls, "connection refused") || strings.Contains(ls, "no route to host") ||
			strings.Contains(ls, "network is unreachable") || strings.Contains(ls, "i/o timeout") ||
			strings.Contains(ls, "context deadline exceeded") || strings.Contains(ls, "no such host") ||
			strings.Contains(ls, "host is down") || strings.Contains(ls, "cannot assign requested address") ||
			strings.Contains(ls, "dial tcp") || strings.Contains(ls, "dial udp") ||
			strings.Contains(ls, "timed out") || strings.Contains(ls, "connection reset") ||
			strings.Contains(ls, "connectex") || strings.Contains(ls, "getsockopt") ||
			strings.Contains(ls, "no route") {
			hasTrans = true
		}
	}
	switch {
	case hasPeer:
		return false, false, true, msg
	case hasSec:
		return false, true, false, msg
	case hasTrans:
		return true, false, false, msg
	default:
		return true, false, false, msg
	}
}

func collectErrStrings(err error) []string {
	out := make([]string, 0, 4)
	// Walk the whole chain for surface strings (top-level wrapper + inner causes).
	cur := err
	for cur != nil {
		out = append(out, cur.Error())
		cur = errors.Unwrap(cur)
	}
	// Also expand libp2p's swarm.DialError into its per-transport causes, which
	// carry the real "connection refused" / "handshake failed" messages that the
	// top-level wrapper ("all dials failed") hides.
	var de *swarm.DialError
	if errors.As(err, &de) {
		for _, te := range de.DialErrors {
			if te.Cause != nil {
				out = append(out, te.Cause.Error())
			}
		}
	}
	return out
}

// finalizeLinkOverall collapses the recorded steps into the overall verdict and
// a human-readable summary for the WebUI.
func finalizeLinkOverall(diag *observer.LinkDiagnosis) {
	failed, skipped := false, false
	for _, s := range diag.Steps {
		if !s.Passed && !s.Skipped {
			failed = true
		}
		if s.Skipped {
			skipped = true
		}
	}
	switch {
	case failed:
		diag.Overall = "fail"
		if diag.Summary == "" {
			diag.Summary = "链路检测失败：存在未通过的关键阶段"
		}
	case skipped:
		diag.Overall = "partial"
		diag.Summary = "链路检测部分完成（部分阶段不适用：需提供含 /p2p/ 的完整 P2P multiaddr）"
	default:
		diag.Overall = "ok"
		diag.Summary = "链路检测全部通过：multiaddr 合法 → DNS → TCP/QUIC → libp2p 传输 → 握手 → Peer ID 匹配 → 连接成功"
	}
}
