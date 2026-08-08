package routing

import (
	"container/heap"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/web"
)

// LinkStatePayload represents a Link State Advertisement (LSA) message broadcasted by peers
type LinkStatePayload struct {
	Origin      string           `json:"origin"`
	Seq         uint64           `json:"seq"`
	TTL         int              `json:"ttl"`
	Neighbors   map[string]int64 `json:"neighbors"` // peerID string -> RTT ms
	Timestamp   int64            `json:"timestamp"`
}

type RouteInfo struct {
	Dest        peer.ID
	NextHop     peer.ID
	Path        []peer.ID
	TotalRTTMs  int64
	DirectRTTMs int64
	IsDirect    bool
}

// Router maintains the global link-state graph and computes shortest paths using Dijkstra's algorithm
type Router struct {
	mu          sync.RWMutex
	localPeerID peer.ID
	graph       map[peer.ID]map[peer.ID]int64 // nodeA -> nodeB -> RTT ms
	seqMap      map[peer.ID]uint64            // origin -> max seq seen
	lastUpdated map[peer.ID]time.Time
}

func NewRouter(localPeerID peer.ID) *Router {
	r := &Router{
		localPeerID: localPeerID,
		graph:       make(map[peer.ID]map[peer.ID]int64),
		seqMap:      make(map[peer.ID]uint64),
		lastUpdated: make(map[peer.ID]time.Time),
	}
	r.graph[localPeerID] = make(map[peer.ID]int64)
	return r
}

// UpdateDirectLink records or updates a direct latency measurement to a peer
func (r *Router) UpdateDirectLink(target peer.ID, rttMs int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.graph[r.localPeerID] == nil {
		r.graph[r.localPeerID] = make(map[peer.ID]int64)
	}

	if rttMs <= 0 {
		rttMs = 1
	}

	r.graph[r.localPeerID][target] = rttMs
	r.lastUpdated[r.localPeerID] = time.Now()
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

	nbrMap := make(map[peer.ID]int64)
	for nbrStr, rtt := range lsa.Neighbors {
		if nbrID, err := peer.Decode(nbrStr); err == nil {
			if rtt <= 0 {
				rtt = 1
			}
			nbrMap[nbrID] = rtt
		}
	}
	r.graph[originID] = nbrMap
	return true
}

// BuildLSA constructs the local node's current LSA payload for broadcasting
func (r *Router) BuildLSA(seq uint64) *LinkStatePayload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	nbrs := make(map[string]int64)
	if localNbrs, ok := r.graph[r.localPeerID]; ok {
		for pID, rtt := range localNbrs {
			nbrs[pID.String()] = rtt
		}
	}

	return &LinkStatePayload{
		Origin:    r.localPeerID.String(),
		Seq:       seq,
		TTL:       5,
		Neighbors: nbrs,
		Timestamp: time.Now().Unix(),
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

	dist := make(map[peer.ID]int64)
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

		for v, weight := range r.graph[u] {
			if visited[v] {
				continue
			}
			newDist := dist[u] + weight
			if newDist < dist[v] {
				dist[v] = newDist
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

		directRTT := int64(0)
		if rtt, ok := directLinks[dest]; ok {
			directRTT = rtt
		}

		routes[dest] = RouteInfo{
			Dest:        dest,
			NextHop:     nextHop,
			Path:        path,
			TotalRTTMs:  d,
			DirectRTTMs: directRTT,
			IsDirect:    nextHop == dest,
		}
	}

	return routes
}

// GetRouteInfoDTOs converts computed routes into web DTOs for dashboard rendering
func (r *Router) GetRouteInfoDTOs(lookup func(pID peer.ID) (nodeName string, tapIP string, tapIPv6 string)) []web.RouteInfoDTO {
	routes := r.ComputeRoutes()
	dtos := make([]web.RouteInfoDTO, 0, len(routes))

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

	for _, route := range routes {
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

		localName := getName(r.localPeerID)
		if localName == "" || (len(r.localPeerID.String()) >= 9 && localName == "..."+r.localPeerID.String()[len(r.localPeerID.String())-9:]) {
			localName = "Local Node"
		}

		candidates := make([]web.CandidatePathDTO, 0)
		if route.DirectRTTMs > 0 {
			isOpt := route.IsDirect
			reason := "Direct P2P link chosen: lowest latency path"
			if !isOpt {
				reason = fmt.Sprintf("Direct P2P link slower (+%d ms vs optimal relay)", route.DirectRTTMs-route.TotalRTTMs)
			}
			candidates = append(candidates, web.CandidatePathDTO{
				PathNames: []string{localName, getName(route.Dest)},
				TotalRTT:  route.DirectRTTMs,
				IsOptimal: isOpt,
				IsDirect:  true,
				Reason:    reason,
			})
		} else {
			candidates = append(candidates, web.CandidatePathDTO{
				PathNames: []string{localName, getName(route.Dest)},
				TotalRTT:  -1,
				IsOptimal: false,
				IsDirect:  true,
				Reason:    "Direct P2P link unreachable (Symmetric NAT / firewall)",
			})
		}

		if !route.IsDirect {
			candidates = append(candidates, web.CandidatePathDTO{
				PathNames: pathNames,
				TotalRTT:  route.TotalRTTMs,
				IsOptimal: true,
				IsDirect:  false,
				Reason:    fmt.Sprintf("Optimal Relay chosen: Saved %d ms latency", savedRTT),
			})
		}

		v4, v6 := getIPs(route.Dest)
		dtos = append(dtos, web.RouteInfoDTO{
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
			Candidates:  candidates,
		})
	}

	return dtos
}
