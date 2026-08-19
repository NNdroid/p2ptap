package routing

import (
	"container/heap"
	"fmt"
	"log"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/observer"
)

// LinkStatePayload represents a Link State Advertisement (LSA) message broadcasted by peers
// DefaultLSATTL is the hop budget stamped on a freshly originated (or replayed)
// link-state advertisement. Each forwarding node decrements it, so it bounds how
// far an LSA travels across the mesh.
const DefaultLSATTL = 5

type LinkStatePayload struct {
	Origin      string           `json:"origin"`
	Seq         uint64           `json:"seq"`
	TTL         int              `json:"ttl"`
	Neighbors      map[string]int64 `json:"neighbors"`                   // peerID string -> RTT ms
	NeighborClasses map[string]int  `json:"neighbor_classes,omitempty"` // peerID string -> LinkClass (0=direct,1=circuit)
	Timestamp   int64            `json:"timestamp"`

	// Node identity piggybacked on every LSA so peers learn name/IP/MAC even when
	// the dedicated meta stream (per-peer NewStream) cannot be established — e.g.
	// on circuit-relay paths where direct sub-stream dials frequently time out.
	NodeName   string `json:"node_name,omitempty"`
	TapIP      string `json:"tap_ip,omitempty"`
	TapIPv6    string `json:"tap_ipv6,omitempty"`
	TapMAC     string `json:"tap_mac,omitempty"`
	OS         string `json:"os,omitempty"`
	Arch       string `json:"arch,omitempty"`
	Version    string `json:"version,omitempty"`
	IsExitNode bool   `json:"is_exit_node,omitempty"`
	// AdvertisedSubnets carries this node's LAN subnets routed across the mesh.
	AdvertisedSubnets []string `json:"advertised_subnets,omitempty"`
}

type RouteInfo struct {
	Dest        peer.ID
	NextHop     peer.ID
	Path        []peer.ID
	TotalRTTMs  int64
	DirectRTTMs int64
	IsDirect    bool
}

// LinkClass distinguishes the transport quality of a link-state edge.
type LinkClass int

const (
	// LinkDirect is a real libp2p QUIC/TCP connection to the peer.
	LinkDirect LinkClass = iota
	// LinkCircuit is a libp2p circuit-relay connection (the peer's built-in
	// relay / a static relay server). It is a shared bottleneck, so the routing
	// cost model penalises it heavily while keeping it reachable as a
	// connectivity fallback.
	LinkCircuit
)

// LinkEdge is one directed link in the link-state graph, carrying both the
// observed latency and its transport class so the router can prefer
// high-quality paths without losing reachability through lower-quality ones.
type LinkEdge struct {
	Weight int64     // observed RTT (ms) — base routing cost
	Class  LinkClass
}

// Routing cost penalties. Kept as package-level so they are trivially tunable.
const (
	// CircuitPenaltyMS is added to the cost of every circuit-relay edge. Circuit
	// relays funnel many peers through one server, so we make them expensive
	// enough that any viable direct or few-hop overlay path is preferred — yet
	// still finite, so a peer reachable ONLY via circuit stays reachable.
	CircuitPenaltyMS int64 = 500
	// HopPenaltyMS is added per traversed edge, so fewer-relay-hop paths win
	// when RTT is comparable.
	HopPenaltyMS int64 = 5
)

// edgeCost maps a link-state edge to its routing cost: observed latency plus a
// class-dependent penalty plus a per-hop penalty. Connectivity is preserved
// (every edge has a finite cost); throughput is maximised (high-quality,
// few-hop paths cost less).
func edgeCost(e LinkEdge) int64 {
	c := e.Weight
	if e.Class == LinkCircuit {
		c += CircuitPenaltyMS
	}
	c += HopPenaltyMS
	return c
}

// Router maintains the global link-state graph and computes shortest paths using Dijkstra's algorithm
type Router struct {
	mu          sync.RWMutex
	localPeerID peer.ID
	graph       map[peer.ID]map[peer.ID]LinkEdge // nodeA -> nodeB -> {RTT ms, class}
	seqMap      map[peer.ID]uint64            // origin -> max seq seen
	lastUpdated map[peer.ID]time.Time
}

func NewRouter(localPeerID peer.ID) *Router {
	r := &Router{
		localPeerID: localPeerID,
		graph:       make(map[peer.ID]map[peer.ID]LinkEdge),
		seqMap:      make(map[peer.ID]uint64),
		lastUpdated: make(map[peer.ID]time.Time),
	}
	r.graph[localPeerID] = make(map[peer.ID]LinkEdge)
	return r
}

// TopologySnapshot is a serializable view of the link-state graph used by the
// WebUI to render the full mesh as a hierarchical tree (relay nodes as parents,
// relayed nodes as children). The graph is populated by LSA flooding, so it may
// contain nodes that are not directly connected to this peer.
type TopologySnapshot struct {
	LocalPeerID peer.ID                       `json:"local_peer_id"`
	Nodes       []peer.ID                     `json:"nodes"`  // every node known to the graph
	Edges       []TopologyEdge                `json:"edges"`  // undirected latency edges (each pair once)
}

// TopologyEdge is one latency edge between two mesh nodes.
//
// Class is carried through from the internal LinkEdge: dropping it here used to
// force every consumer (topology API, WebUI) to render a circuit-relayed link
// identically to a real direct one, which is exactly the distinction an operator
// needs when reading a multi-cluster mesh.
type TopologyEdge struct {
	From  peer.ID   `json:"from"`
	To    peer.ID   `json:"to"`
	RTT   int64     `json:"rtt"`
	Class LinkClass `json:"class"`
}

// GetGraph returns a point-in-time snapshot of the link-state graph.
func (r *Router) GetGraph() TopologySnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	snap := TopologySnapshot{LocalPeerID: r.localPeerID}
	for a := range r.graph {
		snap.Nodes = append(snap.Nodes, a)
	}
	// Emit each undirected edge exactly once. The two directions of a link can
	// legitimately disagree (each endpoint reports its OWN view: A may hold a
	// direct connection while B only knows the circuit-relayed one), so instead
	// of keeping whichever direction map iteration happened to hit first — which
	// made the snapshot non-deterministic across calls — we merge them: the
	// better (lower) class wins, and within the same class the lower RTT wins.
	at := make(map[string]int, len(r.graph))
	for a, nbrs := range r.graph {
		for b, edge := range nbrs {
			key := edgeKey(a, b)
			idx, ok := at[key]
			if !ok {
				at[key] = len(snap.Edges)
				snap.Edges = append(snap.Edges, TopologyEdge{From: a, To: b, RTT: edge.Weight, Class: edge.Class})
				continue
			}
			cur := &snap.Edges[idx]
			if edge.Class < cur.Class {
				cur.Class = edge.Class
				cur.RTT = edge.Weight
			} else if edge.Class == cur.Class && edge.Weight < cur.RTT {
				cur.RTT = edge.Weight
			}
		}
	}
	return snap
}

func edgeKey(a, b peer.ID) string {
	if a < b {
		return string(a) + "|" + string(b)
	}
	return string(b) + "|" + string(a)
}

// GetEdge returns the directed link-state edge from a to b — its observed
// latency and transport class — used by the WebUI traceroute to label each
// forwarding hop with its real transport type and per-leg RTT.
func (r *Router) GetEdge(a, b peer.ID) (LinkEdge, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if m, ok := r.graph[a]; ok {
		if e, ok := m[b]; ok {
			return e, true
		}
	}
	return LinkEdge{}, false
}

// UpdateDirectLink records or updates a link to a peer, setting both its
// observed latency and its transport class.
func (r *Router) UpdateDirectLink(target peer.ID, rttMs int64, class LinkClass) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// A node can never be a direct link to itself. Recording a self-edge
	// (r.graph[localPeerID][localPeerID]) poisons Dijkstra: although the
	// self-edge relaxation is skipped (0+w < 0 is false), a stray self-edge
	// advertised in our own LSA can make the local node appear as a relay hop
	// in its own computed routes, surfacing as "Overlay Relay via <self>" in
	// the WebUI. Guard it at the only direct-link writer without a caller check.
	if target == r.localPeerID {
		return
	}

	if r.graph[r.localPeerID] == nil {
		r.graph[r.localPeerID] = make(map[peer.ID]LinkEdge)
	}

	if rttMs <= 0 {
		rttMs = 1
	}

	r.graph[r.localPeerID][target] = LinkEdge{Weight: rttMs, Class: class}
	r.lastUpdated[r.localPeerID] = time.Now()
}

// UpdateLinkRTT refreshes only the observed latency of an existing edge,
// preserving its transport class. Used by RTT probes / stats loops that
// re-measure a peer without knowing (and without wanting to overwrite) whether
// the underlying libp2p link is direct or circuit. If the edge does not yet
// exist it is created as a direct link (legacy behaviour).
func (r *Router) UpdateLinkRTT(target peer.ID, rttMs int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if rttMs <= 0 {
		rttMs = 1
	}
	if r.graph[r.localPeerID] == nil {
		r.graph[r.localPeerID] = make(map[peer.ID]LinkEdge)
	}
	if e, ok := r.graph[r.localPeerID][target]; ok {
		e.Weight = rttMs
		r.graph[r.localPeerID][target] = e
	} else {
		r.graph[r.localPeerID][target] = LinkEdge{Weight: rttMs, Class: LinkDirect}
	}
	r.lastUpdated[r.localPeerID] = time.Now()
}

// SetEdge records an undirected latency edge between any two mesh nodes. Unlike
// UpdateDirectLink (which is centred on the local node), this lets the topology
// graph represent links learned indirectly — e.g. a peer reached only through a
// bootstrap/relay node, whose hop distance is carried in the peek-map broadcast
// rather than measured by a direct probe. The edge weight is 0-safe (clamped to 1).
func (r *Router) SetEdge(a, b peer.ID, rttMs int64, class LinkClass) {
	if a == b {
		return
	}
	if rttMs <= 0 {
		rttMs = 1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.graph[a] == nil {
		r.graph[a] = make(map[peer.ID]LinkEdge)
	}
	if r.graph[b] == nil {
		r.graph[b] = make(map[peer.ID]LinkEdge)
	}
	r.graph[a][b] = LinkEdge{Weight: rttMs, Class: class}
	r.graph[b][a] = LinkEdge{Weight: rttMs, Class: class}
	r.lastUpdated[a] = time.Now()
	r.lastUpdated[b] = time.Now()
}

// RemoveDirectLink removes a direct link when a peer disconnects
func (r *Router) RemoveDirectLink(target peer.ID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.graph[r.localPeerID] != nil {
		delete(r.graph[r.localPeerID], target)
	}
	delete(r.graph, target)
	delete(r.lastUpdated, target)
	delete(r.seqMap, target)
	for u := range r.graph {
		delete(r.graph[u], target)
	}
}

// CleanStaleNodes purges nodes and link-state entries that haven't sent LSAs within maxAge
func (r *Router) CleanStaleNodes(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	stalePeers := make([]peer.ID, 0)

	for pID, lastTime := range r.lastUpdated {
		if pID == r.localPeerID {
			continue
		}
		if now.Sub(lastTime) > maxAge {
			stalePeers = append(stalePeers, pID)
		}
	}

	for _, pID := range stalePeers {
		delete(r.graph, pID)
		delete(r.lastUpdated, pID)
		delete(r.seqMap, pID)
		if r.graph[r.localPeerID] != nil {
			delete(r.graph[r.localPeerID], pID)
		}
		for u := range r.graph {
			delete(r.graph[u], pID)
		}
	}
}

// ProcessLSA updates the topology graph from a received LSA payload
func (r *Router) ProcessLSA(lsa *LinkStatePayload) bool {
	if lsa == nil || lsa.Origin == "" {
		return false
	}

	originID, err := peer.Decode(lsa.Origin)
	if err != nil {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Ignore stale or duplicate LSA sequence numbers
	if lastSeq, ok := r.seqMap[originID]; ok && lsa.Seq <= lastSeq {
		return false
	}
	r.seqMap[originID] = lsa.Seq
	r.lastUpdated[originID] = time.Now()

	nbrMap := make(map[peer.ID]LinkEdge)
	for nbrStr, rtt := range lsa.Neighbors {
		if nbrID, err := peer.Decode(nbrStr); err == nil {
			// A node is never its own direct neighbour. A self-entry in an LSA
			// would create a graph self-edge (r.graph[originID][originID]) that,
			// once re-advertised in our own LSA, makes the local node show up as
			// its own overlay-relay hop. Drop such entries on ingest.
			if nbrID == originID {
				continue
			}
			if rtt <= 0 {
				rtt = 1
			}
			// Class is carried in NeighborClasses when the origin knows it;
			// older peers that omit the field default to Direct (the historical
			// behaviour), so the wire change is backward compatible.
			class := LinkDirect
			if c, ok := lsa.NeighborClasses[nbrStr]; ok {
				class = LinkClass(c)
			}
			nbrMap[nbrID] = LinkEdge{Weight: rtt, Class: class}
		}
	}
	r.graph[originID] = nbrMap
	return true
}

// BuildLSA constructs the local node's current LSA payload for broadcasting
// NodeIdentity carries the lightweight node info piggybacked onto every LSA so
// peers can learn name/IP/MAC without a separate meta stream negotiation.
type NodeIdentity struct {
	NodeName   string
	TapIP      string
	TapIPv6    string
	TapMAC     string
	OS         string
	Arch       string
	Version    string
	IsExitNode bool
	// AdvertisedSubnets carries this node's LAN subnets routed across the mesh,
	// so peers that learn identity via the LSA broadcast (the "LSA / Peek-Map"
	// channel) also learn subnet routes — not just peers reached via the direct
	// P2P meta stream.
	AdvertisedSubnets []string
}

func (r *Router) BuildLSA(seq uint64, id NodeIdentity) *LinkStatePayload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	nbrs := make(map[string]int64)
	nbrClasses := make(map[string]int)
	if localNbrs, ok := r.graph[r.localPeerID]; ok {
		for pID, edge := range localNbrs {
			nbrs[pID.String()] = edge.Weight
			nbrClasses[pID.String()] = int(edge.Class)
		}
	}

	return &LinkStatePayload{
		Origin:          r.localPeerID.String(),
		Seq:             seq,
		TTL:             DefaultLSATTL,
		Neighbors:       nbrs,
		NeighborClasses: nbrClasses,
		Timestamp:       time.Now().Unix(),
		NodeName:    id.NodeName,
		TapIP:       id.TapIP,
		TapIPv6:     id.TapIPv6,
		TapMAC:      id.TapMAC,
		OS:          id.OS,
		Arch:        id.Arch,
		Version:     id.Version,
		IsExitNode:  id.IsExitNode,
		AdvertisedSubnets: id.AdvertisedSubnets,
	}
}

// Item for priority queue in Dijkstra algorithm
// Item for priority queue in Dijkstra algorithm
type priorityItem struct {
	node  peer.ID
	dist  int64
	index int
}

type priorityQueue []*priorityItem

func (pq priorityQueue) Len() int           { return len(pq) }
func (pq priorityQueue) Less(i, j int) bool { return pq[i].dist < pq[j].dist }
func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}
func (pq *priorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*priorityItem)
	item.index = n
	*pq = append(*pq, item)
}
func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*pq = old[0 : n-1]
	return item
}

// ComputeRoutes runs Dijkstra's algorithm to calculate shortest latency paths to all reachable nodes
func (r *Router) ComputeRoutes() map[peer.ID]RouteInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	dist := make(map[peer.ID]int64)    // penalised cost — drives path selection
	rttDist := make(map[peer.ID]int64) // observed RTT sum — drives display only
	prev := make(map[peer.ID]peer.ID)

	// Gather all unique vertices (source & destination nodes) in graph
	vertices := make(map[peer.ID]bool)
	for u, nbrs := range r.graph {
		vertices[u] = true
		for v := range nbrs {
			vertices[v] = true
		}
	}

	for v := range vertices {
		dist[v] = math.MaxInt64
	}
	dist[r.localPeerID] = 0
	rttDist[r.localPeerID] = 0

	pq := &priorityQueue{}
	heap.Init(pq)
	heap.Push(pq, &priorityItem{
		node: r.localPeerID,
		dist: 0,
	})

	visited := make(map[peer.ID]bool)

	for pq.Len() > 0 {
		curr := heap.Pop(pq).(*priorityItem)
		u := curr.node

		if visited[u] {
			continue
		}
		visited[u] = true

		for v, edge := range r.graph[u] {
			// Never relax a self-edge (u == v). Even though 0+w < 0 is false
			// so dist[u] is never improved through it, skipping keeps the graph
			// clean and avoids any chance of the local node becoming its own
			// relay hop in reconstructed paths.
			if v == u {
				continue
			}
			if visited[v] {
				continue
			}
			// Selection cost uses the class-aware edgeCost (circuit penalised,
			// per-hop penalty). Display RTT accumulates the raw observed weight.
			newDist := dist[u] + edgeCost(edge)
			newRTT := rttDist[u] + edge.Weight
			if newDist < dist[v] {
				dist[v] = newDist
				rttDist[v] = newRTT
				prev[v] = u

				heap.Push(pq, &priorityItem{
					node: v,
					dist: newDist,
				})
			}
		}
	}

	routes := make(map[peer.ID]RouteInfo)
	directLinks := r.graph[r.localPeerID]

	// Reconstruct paths from prev map
	for dest, d := range dist {
		if dest == r.localPeerID || d == math.MaxInt64 {
			continue
		}

		// Backtrack path from dest -> localPeerID
		path := []peer.ID{dest}
		curr := dest
		for curr != r.localPeerID {
			p, ok := prev[curr]
			if !ok {
				break
			}
			path = append(path, p)
			curr = p
		}

		// Reverse path so it goes localPeerID -> hop1 -> ... -> dest
		for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
			path[i], path[j] = path[j], path[i]
		}

		nextHop := dest
		if len(path) > 1 {
			nextHop = path[1]
		}

		// A route whose first hop is the local node itself is meaningless: you
		// cannot relay a frame through yourself. This can only arise from a
		// graph inconsistency (e.g. a stray self-edge that slipped past the
		// ingest guards). Drop the route so the destination falls back to
		// "Overlay Relay (Multi-Hop)" / unreachable instead of being silently
		// looped back to the local node.
		if nextHop == r.localPeerID {
			log.Printf("ComputeRoutes: dropping inconsistent route to %s whose next hop is the local node itself", dest.String())
			continue
		}

		directRTT := int64(0)
		if e, ok := directLinks[dest]; ok {
			directRTT = e.Weight
		}

		routes[dest] = RouteInfo{
			Dest:        dest,
			NextHop:     nextHop,
			Path:        path,
			TotalRTTMs:  rttDist[dest],
			DirectRTTMs: directRTT,
			IsDirect:    nextHop == dest,
		}
	}

	return routes
}

// ─────────────────────────────────────────────────────────────────────────────
// Network Map Export (for bootstrap peers)
// ─────────────────────────────────────────────────────────────────────────────

// NetworkMapEntry is a single node's identity in the exported network map.
type NetworkMapEntry struct {
	PeerID     string `json:"peer_id"`
	NodeName   string `json:"node_name,omitempty"`
	TapIP      string `json:"tap_ip,omitempty"`
	TapIPv6    string `json:"tap_ipv6,omitempty"`
	TapMAC     string `json:"tap_mac,omitempty"`
	OS         string `json:"os,omitempty"`
	Arch       string `json:"arch,omitempty"`
	Version    string `json:"version,omitempty"`
	IsExitNode bool   `json:"is_exit_node,omitempty"`
	// AdvertisedSubnets carries this node's LAN subnets routed across the mesh.
	AdvertisedSubnets []string `json:"advertised_subnets,omitempty"`
}

// NetworkMap is the full snapshot of known node identities, used by bootstrap
// peers to distribute the network topology to newly connected clients.
type NetworkMap struct {
	Entries []NetworkMapEntry `json:"entries"`
}

// ExportFullMap produces a snapshot of all nodes currently known to the router
// (i.e. every peer that has sent an LSA).  The caller supplies a lookup that
// resolves a peer.ID into its cached NodeIdentity (name / IP / MAC / …).
func (r *Router) ExportFullMap(lookup func(pID peer.ID) *NodeIdentity) *NetworkMap {
	r.mu.RLock()
	defer r.mu.RUnlock()

	m := &NetworkMap{}
	for pID := range r.graph {
		if pID == r.localPeerID {
			continue
		}
		if lookup == nil {
			m.Entries = append(m.Entries, NetworkMapEntry{PeerID: pID.String()})
			continue
		}
		id := lookup(pID)
		if id == nil {
			m.Entries = append(m.Entries, NetworkMapEntry{PeerID: pID.String()})
			continue
		}
		m.Entries = append(m.Entries, NetworkMapEntry{
			PeerID:     pID.String(),
			NodeName:   id.NodeName,
			TapIP:      id.TapIP,
			TapIPv6:    id.TapIPv6,
			TapMAC:     id.TapMAC,
			OS:         id.OS,
			Arch:       id.Arch,
			Version:    id.Version,
			IsExitNode: id.IsExitNode,
		})
	}
	return m
}

// findSubPath finds the shortest path and latency between src and dst in the graph,
// without visiting the excluded peer (typically the local node, to prevent looping).
func (r *Router) findSubPath(src, dst, exclude peer.ID) ([]peer.ID, int64) {
	if src == dst {
		return []peer.ID{src}, 0
	}
	dist := make(map[peer.ID]int64)
	prev := make(map[peer.ID]peer.ID)
	visited := make(map[peer.ID]bool)

	pq := &priorityQueue{}
	heap.Init(pq)
	dist[src] = 0
	heap.Push(pq, &priorityItem{node: src, dist: 0})

	for pq.Len() > 0 {
		curr := heap.Pop(pq).(*priorityItem)
		u := curr.node
		if u == dst {
			break
		}
		if visited[u] {
			continue
		}
		visited[u] = true

		for v, edge := range r.graph[u] {
			if v == exclude || v == u || visited[v] {
				continue
			}
			newDist := dist[u] + edgeCost(edge)
			if old, ok := dist[v]; !ok || newDist < old {
				dist[v] = newDist
				prev[v] = u
				heap.Push(pq, &priorityItem{node: v, dist: newDist})
			}
		}
	}

	if _, ok := dist[dst]; !ok {
		return nil, -1
	}

	// Backtrack path
	path := []peer.ID{dst}
	curr := dst
	for curr != src {
		p, exists := prev[curr]
		if !exists {
			return nil, -1
		}
		path = append(path, p)
		curr = p
	}
	// Reverse path
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}

	// Calculate raw observed RTT sum for display
	rawRTT := int64(0)
	for i := 0; i < len(path)-1; i++ {
		u := path[i]
		v := path[i+1]
		if edge, ok := r.graph[u][v]; ok {
			rawRTT += edge.Weight
		}
	}

	return path, rawRTT
}

// GetRouteInfoDTOs converts computed routes into observer DTOs for dashboard rendering,
// evaluating all direct and multi-hop candidate paths across the mesh topology.
func (r *Router) GetRouteInfoDTOs(lookup func(pID peer.ID) (nodeName string, tapIP string, tapIPv6 string)) []observer.RouteInfoDTO {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := r.ComputeRoutes()
	dtos := make([]observer.RouteInfoDTO, 0, len(routes))

	getName := func(pID peer.ID) string {
		if lookup != nil {
			name, _, _ := lookup(pID)
			if name != "" {
				return name
			}
		}
		s := pID.String()
		if len(s) >= 9 {
			return "..." + s[len(s)-9:]
		}
		return s
	}

	getIPs := func(pID peer.ID) (string, string) {
		if lookup != nil {
			_, ip, ip6 := lookup(pID)
			return ip, ip6
		}
		return "-", "-"
	}

	localName := getName(r.localPeerID)
	if localName == "" || (len(r.localPeerID.String()) >= 9 && localName == "..."+r.localPeerID.String()[len(r.localPeerID.String())-9:]) {
		localName = "Local Node"
	}

	directLinks := r.graph[r.localPeerID]

	for _, route := range routes {
		dest := route.Dest
		pathStrs := make([]string, len(route.Path))
		pathNames := make([]string, len(route.Path))
		for i, p := range route.Path {
			pathStrs[i] = p.String()
			pathNames[i] = getName(p)
		}

		savedRTT := int64(0)
		if route.DirectRTTMs > 0 && route.TotalRTTMs < route.DirectRTTMs {
			savedRTT = route.DirectRTTMs - route.TotalRTTMs
		}

		// Candidate path discovery:
		// 1. Direct candidate
		// 2. Multi-hop candidates via all other direct neighbors
		type candItem struct {
			pathIDs   []peer.ID
			pathNames []string
			totalRTT  int64
			isDirect  bool
			isOptimal bool
			reason    string
		}

		candidatesMap := make(map[string]*candItem)

		// 1. Evaluate Direct P2P Link
		if directEdge, ok := directLinks[dest]; ok && directEdge.Weight > 0 {
			isOpt := route.IsDirect
			cand := &candItem{
				pathIDs:   []peer.ID{r.localPeerID, dest},
				pathNames: []string{localName, getName(dest)},
				totalRTT:  directEdge.Weight,
				isDirect:  true,
				isOptimal: isOpt,
			}
			if isOpt {
				cand.reason = fmt.Sprintf("Direct P2P link chosen: lowest latency path (%d ms)", directEdge.Weight)
			} else {
				diff := directEdge.Weight - route.TotalRTTMs
				cand.reason = fmt.Sprintf("Direct P2P link slower: %d ms (+%d ms vs optimal relay)", directEdge.Weight, diff)
			}
			key := fmt.Sprintf("%s->%s", r.localPeerID, dest)
			candidatesMap[key] = cand
		} else {
			// Direct unreachable
			cand := &candItem{
				pathIDs:   []peer.ID{r.localPeerID, dest},
				pathNames: []string{localName, getName(dest)},
				totalRTT:  -1,
				isDirect:  true,
				isOptimal: false,
				reason:    "Direct P2P link unreachable (Symmetric NAT / firewall blocked)",
			}
			key := fmt.Sprintf("%s->%s", r.localPeerID, dest)
			candidatesMap[key] = cand
		}

		// 2. Evaluate all 1-hop neighbor transits (Overlay Relays)
		for neighborID, neighborEdge := range directLinks {
			if neighborID == dest || neighborID == r.localPeerID {
				continue
			}
			subPath, subRTT := r.findSubPath(neighborID, dest, r.localPeerID)
			if subPath != nil && subRTT >= 0 {
				fullPath := append([]peer.ID{r.localPeerID}, subPath...)
				fullNames := make([]string, len(fullPath))
				for idx, p := range fullPath {
					fullNames[idx] = getName(p)
				}
				totalRTT := neighborEdge.Weight + subRTT
				isOpt := !route.IsDirect && len(route.Path) == len(fullPath)
				if isOpt {
					for idx := range fullPath {
						if fullPath[idx] != route.Path[idx] {
							isOpt = false
							break
						}
					}
				}

				key := ""
				for _, p := range fullPath {
					key += string(p) + "->"
				}

				cand := &candItem{
					pathIDs:   fullPath,
					pathNames: fullNames,
					totalRTT:  totalRTT,
					isDirect:  false,
					isOptimal: isOpt,
				}

				relayName := getName(neighborID)
				if isOpt {
					if route.DirectRTTMs > 0 {
						cand.reason = fmt.Sprintf("Optimal Relay chosen: Saved %d ms latency (via %s) vs direct (%d ms)", savedRTT, relayName, route.DirectRTTMs)
					} else {
						cand.reason = fmt.Sprintf("Optimal Relay chosen via %s: total latency %d ms (direct P2P unreachable)", relayName, totalRTT)
					}
				} else {
					diff := totalRTT - route.TotalRTTMs
					if diff >= 0 {
						cand.reason = fmt.Sprintf("Sub-optimal transit via %s: total %d ms (+%d ms vs optimal)", relayName, totalRTT, diff)
					} else {
						cand.reason = fmt.Sprintf("Transit candidate via %s (evaluated latency %d ms)", relayName, totalRTT)
					}
				}
				candidatesMap[key] = cand
			} else {
				// Neighbor cannot reach dest
				cand := &candItem{
					pathIDs:   []peer.ID{r.localPeerID, neighborID, dest},
					pathNames: []string{localName, getName(neighborID), getName(dest)},
					totalRTT:  -1,
					isDirect:  false,
					isOptimal: false,
					reason:    fmt.Sprintf("Relay transit unreachable: intermediate node %s cannot route to destination", getName(neighborID)),
				}
				key := fmt.Sprintf("%s->%s->%s", r.localPeerID, neighborID, dest)
				candidatesMap[key] = cand
			}
		}

		// Convert map to slice and sort
		candList := make([]*candItem, 0, len(candidatesMap))
		for _, c := range candidatesMap {
			candList = append(candList, c)
		}

		sort.SliceStable(candList, func(i, j int) bool {
			// Optimal first
			if candList[i].isOptimal != candList[j].isOptimal {
				return candList[i].isOptimal
			}
			// Reachable before unreachable
			if (candList[i].totalRTT > 0) != (candList[j].totalRTT > 0) {
				return candList[i].totalRTT > 0
			}
			// Lower RTT first
			if candList[i].totalRTT > 0 && candList[j].totalRTT > 0 && candList[i].totalRTT != candList[j].totalRTT {
				return candList[i].totalRTT < candList[j].totalRTT
			}
			// Direct before relay on tie
			if candList[i].isDirect != candList[j].isDirect {
				return candList[i].isDirect
			}
			return len(candList[i].pathIDs) < len(candList[j].pathIDs)
		})

		candidatesDTO := make([]observer.CandidatePathDTO, len(candList))
		for idx, c := range candList {
			candidatesDTO[idx] = observer.CandidatePathDTO{
				PathNames: c.pathNames,
				TotalRTT:  c.totalRTT,
				IsOptimal: c.isOptimal,
				IsDirect:  c.isDirect,
				Reason:    c.reason,
			}
		}

		v4, v6 := getIPs(route.Dest)
		dtos = append(dtos, observer.RouteInfoDTO{
			DestPeer:    route.Dest.String(),
			DestName:    getName(route.Dest),
			TapIP:       v4,
			TapIPv6:     v6,
			NextHopPeer: route.NextHop.String(),
			NextHopName: getName(route.NextHop),
			Path:        pathStrs,
			PathNames:   pathNames,
			IsDirect:    route.IsDirect,
			TotalRTTMs:  route.TotalRTTMs,
			DirectRTTMs: route.DirectRTTMs,
			SavedRTTMs:  savedRTT,
			Candidates:  candidatesDTO,
		})
	}

	return dtos
}

