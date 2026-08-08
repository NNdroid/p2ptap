package node

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"time"

	"p2ptap/pkg/meta"
	"p2ptap/pkg/tap"
	"p2ptap/pkg/version"
	"p2ptap/pkg/web"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func (n *Node) registerMetaStreamHandler() {
	startTime := time.Now()
	n.Host.SetStreamHandler(meta.MetaProtocolID, func(s network.Stream) {
		defer s.Close()
		remotePeer := s.Conn().RemotePeer()

		data, err := io.ReadAll(io.LimitReader(s, 4096))
		if err == nil && len(data) > 0 {
			var payload meta.NodeMetaPayload
			if err := json.Unmarshal(data, &payload); err == nil {
				n.peerMeta.Store(remotePeer, PeerMeta{
					NodeName:     payload.NodeName,
					TapIP:        payload.TapIP,
					TapIPv6:      payload.TapIPv6,
					TapMAC:       payload.TapMAC,
					OSArch:       fmt.Sprintf("%s/%s", payload.OS, payload.Arch),
					Version:      payload.Version,
					UptimeSec:    payload.UptimeSec,
					Reachability: payload.Reachability,
					IsExitNode:   payload.IsExitNode,
					ExitNAT:      payload.ExitNAT,
					TxSpeed:      payload.TxSpeed,
					RxSpeed:      payload.RxSpeed,
					TotalTx:           payload.TotalTx,
					TotalRx:           payload.TotalRx,
					AdvertisedSubnets: payload.AdvertisedSubnets,
					LastSync:          time.Now(),
				})
			n.processSubnetRoutes(remotePeer, payload.TapIP, payload.TapIPv6, payload.AdvertisedSubnets)
			if payload.TapMAC != "" {
					if hw, err := net.ParseMAC(payload.TapMAC); err == nil && len(hw) == 6 {
						n.MACTable.Learn(hw, remotePeer)
						cleanIP := strings.Split(payload.TapIP, "/")[0]
						cleanv6 := strings.Split(payload.TapIPv6, "/")[0]
						if setter, ok := n.TAP.(interface{ RegisterIPMAC(string, string) }); ok {
							if cleanIP != "" {
								setter.RegisterIPMAC(cleanIP, payload.TapMAC)
							}
							if cleanv6 != "" {
								setter.RegisterIPMAC(cleanv6, payload.TapMAC)
							}
						}
						if ip := net.ParseIP(cleanIP); ip != nil && len(ip.To4()) == 4 && n.TAP != nil {
							garpFrame := tap.BuildARPReplyFrame(hw, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ip, ip)
							_, _ = n.TAP.Write(garpFrame)
						}
						if ip6 := net.ParseIP(cleanv6); ip6 != nil && ip6.To16() != nil && n.TAP != nil {
							naFrame := tap.BuildIPv6NeighborAdvertisementFrame(hw, ip6)
							if len(naFrame) > 0 {
								_, _ = n.TAP.Write(naFrame)
							}
						}
					}
				}
				log.Debug("Received metadata sync from peer %s: name=%s os=%s/%s tap_ip=%s mac=%s ver=%s exit_node=%v tx_speed=%d rx_speed=%d",
					remotePeer.String(), payload.NodeName, payload.OS, payload.Arch, payload.TapIP, payload.TapMAC, payload.Version, payload.IsExitNode, payload.TxSpeed, payload.RxSpeed)
			}
		}

		// Respond with local node's metadata
		localTxRx := web.TxRxStats{}
		if n.Collector != nil {
			localTxRx = n.Collector.GetTxRxStats()
		}
		respPayload := meta.NodeMetaPayload{
			NodeName:     n.Config.NodeName,
			TapIP:        n.Config.TapIP,
			TapIPv6:      n.Config.TapIPv6,
			TapMAC:       n.Config.TapMAC,
			OS:           runtime.GOOS,
			Arch:         runtime.GOARCH,
			Version:      version.Version,
			UptimeSec:    int64(time.Since(startTime).Seconds()),
			Reachability: "P2P Node",
			IsExitNode:   n.Config.ExitNode.Enable,
			ExitNAT:      n.Config.ExitNode.NATMasquerade,
			TxSpeed:      localTxRx.TxSpeed,
			RxSpeed:      localTxRx.RxSpeed,
			TotalTx:           localTxRx.TotalTx,
			TotalRx:           localTxRx.TotalRx,
			AdvertisedSubnets: n.Config.AdvertisedSubnets,
		}
		if respBytes, err := json.Marshal(respPayload); err == nil {
			_, _ = s.Write(respBytes)
		}
	})
	log.Debug("Stream handler registered for metadata protocol: %s", meta.MetaProtocolID)
}

func (n *Node) metaSyncLoop() {
	defer n.wg.Done()
	startTime := time.Now()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Initial sync immediately after startup
	time.Sleep(2 * time.Second)
	n.broadcastMetadata(startTime)

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.broadcastMetadata(startTime)
		}
	}
}

func (n *Node) getAllPeersForMetaSync() []peer.ID {
	seen := make(map[peer.ID]bool)
	list := make([]peer.ID, 0)
	for _, p := range n.Host.Network().Peers() {
		if !seen[p] {
			seen[p] = true
			list = append(list, p)
		}
	}
	for _, entry := range n.MACTable.GetAllEntries() {
		if entry.PeerID != "" && entry.PeerID != n.Host.ID() && !seen[entry.PeerID] {
			seen[entry.PeerID] = true
			list = append(list, entry.PeerID)
		}
	}
	for targetPeer := range n.Router.ComputeRoutes() {
		if targetPeer != "" && targetPeer != n.Host.ID() && !seen[targetPeer] {
			seen[targetPeer] = true
			list = append(list, targetPeer)
		}
	}
	return list
}

func (n *Node) broadcastMetadata(startTime time.Time) {
	peers := n.getAllPeersForMetaSync()
	if len(peers) == 0 {
		return
	}

	// Self-reachability: "Public" if ANY peer has a direct (non-circuit) transport link.
	// Only downgrade to "Relay" if ALL connections go through p2p-circuit relays,
	// which means this node cannot form direct transport connections.
	reachability := "Relay"
	for _, p := range peers {
		conns := n.Host.Network().ConnsToPeer(p)
		if len(conns) == 0 {
			continue // no transport connections to this peer
		}
		allCircuits := true
		for _, conn := range conns {
			if !strings.Contains(conn.RemoteMultiaddr().String(), "/p2p-circuit") {
				allCircuits = false
				break
			}
		}
		if !allCircuits {
			reachability = "Public"
			break // found at least one direct connection, no need to check further
		}
		// allConnections are circuit-relay → still relay, check next peer
	}

	localTxRx := web.TxRxStats{}
	if n.Collector != nil {
		localTxRx = n.Collector.GetTxRxStats()
	}

	payload := meta.NodeMetaPayload{
		NodeName:     n.Config.NodeName,
		TapIP:        n.Config.TapIP,
		TapIPv6:      n.Config.TapIPv6,
		TapMAC:       n.Config.TapMAC,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Version:      version.Version,
		UptimeSec:    int64(time.Since(startTime).Seconds()),
		Reachability: reachability,
		IsExitNode:   n.Config.ExitNode.Enable,
		ExitNAT:      n.Config.ExitNode.NATMasquerade,
		TxSpeed:      localTxRx.TxSpeed,
		RxSpeed:      localTxRx.RxSpeed,
		TotalTx:           localTxRx.TotalTx,
		TotalRx:           localTxRx.TotalRx,
		AdvertisedSubnets: n.Config.AdvertisedSubnets,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	// Semaphore to limit concurrent meta sync goroutines, preventing network storm.
	const maxConcurrentSync = 8
	sem := make(chan struct{}, maxConcurrentSync)

	for _, pID := range peers {
		targetPeer := pID
		sem <- struct{}{} // Acquire slot
		go func() {
			defer func() { <-sem }() // Release slot
			ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
			defer cancel()

			s, err := n.Host.NewStream(ctx, targetPeer, meta.MetaProtocolID)
			if err != nil {
				return
			}
			defer s.Close()
			if _, err := s.Write(data); err != nil {
				log.Warn("Meta sync write to %s failed: %v", targetPeer.String(), err)
				return
			}
			if err := s.CloseWrite(); err != nil {
				log.Warn("Meta sync closeWrite to %s failed: %v", targetPeer.String(), err)
			}

			respData, err := io.ReadAll(io.LimitReader(s, 4096))
			if err == nil && len(respData) > 0 {
				var respPayload meta.NodeMetaPayload
				if err := json.Unmarshal(respData, &respPayload); err == nil && respPayload.NodeName != "" {
					n.peerMeta.Store(targetPeer, PeerMeta{
						NodeName:     respPayload.NodeName,
						TapIP:        respPayload.TapIP,
						TapIPv6:      respPayload.TapIPv6,
						TapMAC:       respPayload.TapMAC,
						OSArch:       fmt.Sprintf("%s/%s", respPayload.OS, respPayload.Arch),
						Version:      respPayload.Version,
						UptimeSec:    respPayload.UptimeSec,
						Reachability: respPayload.Reachability,
						IsExitNode:   respPayload.IsExitNode,
						ExitNAT:      respPayload.ExitNAT,
						TxSpeed:      respPayload.TxSpeed,
						RxSpeed:      respPayload.RxSpeed,
						TotalTx:           respPayload.TotalTx,
						TotalRx:           respPayload.TotalRx,
						AdvertisedSubnets: respPayload.AdvertisedSubnets,
						LastSync:          time.Now(),
					})
				n.processSubnetRoutes(targetPeer, respPayload.TapIP, respPayload.TapIPv6, respPayload.AdvertisedSubnets)
				if respPayload.TapMAC != "" {
						if hw, err := net.ParseMAC(respPayload.TapMAC); err == nil && len(hw) == 6 {
							n.MACTable.Learn(hw, targetPeer)
							cleanIP := strings.Split(respPayload.TapIP, "/")[0]
							cleanv6 := strings.Split(respPayload.TapIPv6, "/")[0]
							if setter, ok := n.TAP.(interface{ RegisterIPMAC(string, string) }); ok {
								if cleanIP != "" {
									setter.RegisterIPMAC(cleanIP, respPayload.TapMAC)
								}
								if cleanv6 != "" {
									setter.RegisterIPMAC(cleanv6, respPayload.TapMAC)
								}
							}
							if ip := net.ParseIP(cleanIP); ip != nil && len(ip.To4()) == 4 && n.TAP != nil {
								garpFrame := tap.BuildARPReplyFrame(hw, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ip, ip)
								_, _ = n.TAP.Write(garpFrame)
							}
							if ip6 := net.ParseIP(cleanv6); ip6 != nil && ip6.To16() != nil && n.TAP != nil {
								naFrame := tap.BuildIPv6NeighborAdvertisementFrame(hw, ip6)
								if len(naFrame) > 0 {
									_, _ = n.TAP.Write(naFrame)
								}
							}
						}
					}
				}
			}
		}()
	}
}

func (n *Node) processSubnetRoutes(remotePeer peer.ID, tapIPv4, tapIPv6 string, subnets []string) {
	if len(subnets) == 0 || !n.Config.AcceptAdvertisedSubnets {
		return
	}

	isAllowed := false
	for _, p := range n.Config.AllowedSubnetPeers {
		if p == "*" || p == remotePeer.String() {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		log.Debug("🔒 Subnet route from peer %s ignored (not in allowed_subnet_peers)", remotePeer.String())
		return
	}

	cleanGWv4 := strings.Split(tapIPv4, "/")[0]
	cleanGWv6 := strings.Split(tapIPv6, "/")[0]

	for _, sub := range subnets {
		if sub == "" {
			continue
		}

		// Pick correct gateway based on subnet address family.
		var gw string
		if _, subnetNet, err := net.ParseCIDR(sub); err == nil {
			if subnetNet.IP.To4() != nil {
				gw = cleanGWv4
			} else {
				gw = cleanGWv6
			}
		} else {
			continue
		}

		if gw == "" {
			log.Warn("No gateway available for subnet %s: remote peer %s has no matching IP on the overlay",
				sub, remotePeer.String())
			continue
		}

		installed, err := n.Gateway.AddSubnetRoute(sub, gw)
		if err != nil {
			log.Warn("Failed to install subnet route %s via %s: %v", sub, gw, err)
		} else if installed {
			log.Info("🌐 Successfully installed authorized subnet route %s via peer %s (%s)", sub, remotePeer.String(), gw)
		}
	}
}
