package config

// RestartRequiredFields is the single definition of "changing this field has no
// runtime effect until the process restarts".
//
// A field belongs here when every one of its consumers reads it from the
// construction-time Config baseline, or calls it exactly once while building the
// libp2p host / TAP device. Publishing such a field through a hot reload only
// swaps the config snapshot; nothing in the running process observes it. If the
// UI does not say so, the operator sees "saved and applied" while the running
// node keeps the old behaviour — the setting appears to work and does not.
//
// Everything NOT listed here is genuinely hot-reloadable: applyHotReload
// re-applies the obfuscation packer and exit-node NAT, and the remaining
// consumers (STUN/TURN resolution, key negotiation, boot-mesh discovery,
// subnet arbitration and routing) read the live snapshot on every use.
//
// This is the one place the list is maintained. Consumers:
//   - pkg/web  warns the mesh WebUI "saved, but these need a restart"
//   - callers that plan a reload (Android) instead of keeping a second,
//     hand-written copy that silently drifts from reality
//
// When you add a config field, decide here — not in the caller — whether its
// first and last read happen at construction time.
func RestartRequiredFields(old, new *Config) []string {
	if old == nil || new == nil {
		return nil
	}
	var out []string
	add := func(name string, changed bool) {
		if changed {
			out = append(out, name)
		}
	}

	// TAP device: created once from these values at node construction.
	add("tap_name", old.TapName != new.TapName)
	add("tap_ip", old.TapIP != new.TapIP)
	add("tap_ipv6", old.TapIPv6 != new.TapIPv6)
	add("tap_mac", old.TapMAC != new.TapMAC)
	add("mtu", old.MTU != new.MTU)
	add("driver_type", old.DriverType != new.DriverType)
	add("listen_addrs", !sliceEqual(old.ListenAddrs, new.ListenAddrs))

	// Transports: EnableRelay / EnableHolePunching / EnableAutoRelayWithStaticRelays
	// are libp2p options consumed by libp2p.New, and TLSServerName / TLSSNISuffix
	// are written once through global setters before it. The whole block is bound
	// for the life of the host, so compare it wholesale.
	add("transports", old.Transports != new.Transports)

	add("bootstrap_peers", !sliceEqual(old.BootstrapPeers, new.BootstrapPeers))
	add("static_peers", !sliceEqual(old.StaticPeers, new.StaticPeers))

	// MDNS discovery service is instantiated once, gated on the flag.
	add("enable_mdns", old.EnableMDNS != new.EnableMDNS)
	// ForcePrivateReachability becomes the libp2p ForceReachabilityPrivate option.
	add("force_private_reachability", old.ForcePrivateReachability != new.ForcePrivateReachability)

	// The PSK invalidates every PSK-bound per-peer key; it is applied at startup
	// (transport pnet + SeqSync salt), so it needs a restart.
	add("psk", old.PSK != new.PSK)
	add("transport_strategy", old.TransportStrategy != new.TransportStrategy)

	// Only the WebUI bind/port/enable/token need a restart: the running Server
	// resolves its bearer token once at startup; pcap_sample_every is read
	// live and stays excluded.
	add("web_ui", old.WebUI.Enable != new.WebUI.Enable ||
		old.WebUI.ListenIP != new.WebUI.ListenIP ||
		old.WebUI.ListenIPv6 != new.WebUI.ListenIPv6 ||
		old.WebUI.Port != new.WebUI.Port ||
		old.WebUI.AuthToken != new.WebUI.AuthToken)

	// Node name still updates the local display live via the collector, but
	// peer-anchored identity — meta/peek-map/LSA — keeps the boot value.
	add("node_name", old.NodeName != new.NodeName)

	// Both timeouts are partially frozen at host construction and cannot be
	// unwound: hole_punch_timeout seeds the libp2p EnableHolePunching
	// DirectDialTimeout, and relay_upgrade_interval is read once when the
	// relay-only upgrade goroutine creates its ticker. The running value keeps
	// applying for the paths that read the live snapshot, which makes a save
	// look half-applied — a warning beats that silence.
	add("hole_punch_timeout", old.HolePunchTimeout != new.HolePunchTimeout)
	add("relay_upgrade_interval", old.RelayUpgradeInterval != new.RelayUpgradeInterval)

	return out
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
