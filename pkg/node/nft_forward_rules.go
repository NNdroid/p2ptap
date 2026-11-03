package node

// forwardDirection is which interface a forward rule matches on.
type forwardDirection int

const (
	// forwardIn matches the ingress interface (packets entering from the TAP).
	forwardIn forwardDirection = iota
	// forwardOut matches the egress interface (packets leaving towards the TAP).
	forwardOut
)

// forwardAcceptRule is a platform-neutral description of one rule that lets
// tunneled client traffic cross the netfilter FORWARD hook. It exists because
// the nftables expression types cannot be built (or even imported) off Linux,
// and these rules are the difference between a working exit node and one that
// installs NAT and then drops every byte.
//
// The Linux implementation translates each rule to nftables expressions in
// this fixed order: interface match, optional conntrack-state test, accept.
type forwardAcceptRule struct {
	Iface string
	Dir   forwardDirection
	// Established requires conntrack state to be ESTABLISHED or RELATED, so a
	// remote host cannot reach a mesh client that never opened the connection.
	Established bool
}

// forwardAcceptRules returns the rules needed to make an Exit Node work on a
// host whose FORWARD policy is DROP — the default on any machine running
// Docker (which sets "-P FORWARD DROP") and on ufw/firewalld defaults.
//
// Both directions are needed. Accepting only the outbound direction leaves
// replies unable to come back, which looks identical to a dead tunnel.
//
// Every rule is scoped to a device this process created and named; nothing
// here widens forwarding for any other traffic on the host, and no rule drops
// anything, so the host's own policy still governs everything else.
func forwardAcceptRules(tapIfName string) []forwardAcceptRule {
	if tapIfName == "" {
		return nil
	}
	return []forwardAcceptRule{
		// Client -> egress. Matched by ingress interface only: the NAT chain
		// decides which egress interface the traffic may actually use.
		{Iface: tapIfName, Dir: forwardIn},
		// Egress -> client, restricted to return traffic. A bare
		// "oifname <tap> accept" would also deliver any packet a WAN-side
		// network happens to route at the TAP subnet, which matters because
		// overlapping RFC1918 space is common behind an exit node.
		{Iface: tapIfName, Dir: forwardOut, Established: true},
	}
}
