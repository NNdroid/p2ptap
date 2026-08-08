// Package meta defines the shared wire format for P2P node metadata exchange
// over the /p2ptap/meta/1.0.0 libp2p protocol.
package meta

const MetaProtocolID = "/p2ptap/meta/1.0.0"

// NodeMetaPayload is the JSON-serialized metadata exchanged between p2ptap nodes
// (and optionally bootstrap/relay servers).  All fields are sent over the wire;
// non-applicable fields should be left at their zero values.
type NodeMetaPayload struct {
	NodeName          string   `json:"node_name"`
	TapIP             string   `json:"tap_ip"`
	TapIPv6           string   `json:"tap_ipv6"`
	TapMAC            string   `json:"tap_mac"`
	OS                string   `json:"os"`
	Arch              string   `json:"arch"`
	Version           string   `json:"version"`
	UptimeSec         int64    `json:"uptime_sec"`
	Reachability      string   `json:"reachability"`
	IsExitNode        bool     `json:"is_exit_node"`
	ExitNAT           bool     `json:"exit_nat"`
	TxSpeed           uint64   `json:"tx_speed"`
	RxSpeed           uint64   `json:"rx_speed"`
	TotalTx           uint64   `json:"total_tx"`
	TotalRx           uint64   `json:"total_rx"`
	AdvertisedSubnets []string `json:"advertised_subnets"`
}
