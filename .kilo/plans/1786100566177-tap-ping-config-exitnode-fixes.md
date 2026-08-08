# Fix TAP Data Transfer (ping), Config Save, and Exit-Node Interfaces

## Context
User reports (benchmark vs ZeroTier): connected to peer, but **cannot ping peer's TAP IP**; the
**config-save API** and the **exit-node API** are both broken. Three independent bug clusters, all in
`pkg/node` and `pkg/web`. No new features — only correct existing behavior.

## Root-Cause Findings

### A. Ping failure (TAP data transfer) — relay path
File: `pkg/node/node.go` → `handleRelayStream` (lines 1663–1713)
- **Bug A1 (critical): inverted MAC-learning condition.** `ExtractEthernetMACs` returns `err=true` on
  FAILURE (see `pkg/switch/mac_table.go:153`). The relay handler uses `if ... ; !ok { Learn(...) }`
  (line 1678), so it learns MACs ONLY when parsing FAILS (garbage), and NEVER learns the real source
  MAC for successfully parsed relayed frames. Contrast the correct usage at `node.go:706-708`
  (`if !errExtract { Learn }`). Result: MAC table stays empty for relayed peers → unicast fails,
  return traffic (the ping reply) cannot be routed to the originator.
- **Bug A2: no local-dest MAC fixup in relay path.** `handleStream` (lines 729–739) overwrites
  `payload[0:6]` with `n.localMAC` when `dstIP == n.localV4IP` (so the kernel accepts the frame).
  `handleRelayStream` writes the raw relayed payload to TAP with NO such fixup, so if the inner
  dstMAC ≠ local MAC the kernel drops it (the ICMP echo reply never reaches the OS).
- **Bug A3: relay path skips ACL + WebUI interceptor.** `handleRelayStream` writes straight to TAP
  without `MatchACL` and without `Interceptor.MatchAndHandle`, unlike `handleStream`. Inconsistent
  and a silent security gap.

### B. Config-save API writes partial config / drops fields
File: `pkg/config/config.go` → `UpdateConfigFileDelta`; callers `pkg/web/server.go` (POST
`/api/config`) and `pkg/web/interceptor.go` (POST `/api/config`).
- **Bug B1 (critical): partial saves clobber fields.** WebUI sends only the fields its form touches.
  `json.NewDecoder.Decode(&incoming)` leaves non-sent slices/pointers at zero value, so
  `rawMap["advertised_subnets"] = incoming.AdvertisedSubnets` etc. overwrite on-disk values with
  `null`/`[]`, wiping user's subnets/ACL. (Note `UpdateConfigFileDelta` already preserves immutable
  fields like tap_ip/mtu, so the issue is the *mutable* fields that the form omits.)
- **Bug B2: in-memory config not applied for subnet/ACL fields.** After save, `server.go:606-614`
  and `interceptor.go:577-585` hot-reload only node_name/strategy/psk/log_level/obfuscation/
  bootstrap/static/mdns/exit_node. They omit `AdvertisedSubnets`, `AcceptAdvertisedSubnets`,
  `AllowedSubnetPeers`, and `ACL` → changes only take effect after restart, and the live metadata/
  subnet-route logic keeps using stale values.

### C. Exit-node API
File: `pkg/node/gateway.go`, `pkg/web/server.go` (`/api/exitnode`), `pkg/node/node.go` (`Start`).
- **Bug C1 (critical): runtime enable never sets up NAT/IP-forwarding.** `node.go:488` calls
  `NFTManager.SetupExitNodeNAT` only when `ExitNode.Enable` is true at `Start()`. The WebUI
  `/api/exitnode` action `set` calls `Gateway.SetExitNode` directly and NEVER calls
  `SetupExitNodeNAT`/`EnableIPForwarding`, so a node turned into an exit node at runtime does not
  actually forward/masquerade traffic. (On Linux `EnableIPForwarding` lives inside
  `SetupExitNodeNAT`; on non-Linux it is a no-op stub in `nftables_others.go`.)
- **Bug C2: WebUI passes `nil` physical endpoints.** `server.go:544` calls
  `SetExitNode(peerID, cleanIP, nil)`. `SetExitNode` then adds the `0.0.0.0/0` default route through
  the TAP without protecting the P2P relay/endpoint sockets (`ProtectEndpoint` is never called),
  creating a routing loop where P2P control traffic is captured by the TAP default route.
- **Bug C3: no underlying physical-gateway fallback if detection fails.** Acceptable to keep, but
  `SetExitNode` silently continues with `originalPhysicalGW == ""` and skips endpoint protection
  (compounds C2). Plan: require a detected gateway (or pass endpoints from caller) before applying the
  default route.

## Implementation Tasks

### 1. Fix relay data path (`pkg/node/node.go`)
- **1a.** In `handleRelayStream`, change line 1678 from `if ... ; !ok {` to `if ... ; ok {` (learn
  only when extraction succeeds). Move the `Learn` out so it executes for the success case, mirroring
  `node.go:706-708`. Use `s.Conn().RemotePeer()`.
- **1b.** Add the same local-dest MAC fixup used in `handleStream` (lines 729–739) inside the
  `finalDst == n.Host.ID()` branch of `handleRelayStream`, before `n.TAP.Write`. Guard on
  `n.localV4IP`/`n.localV6IP`/`n.localMAC` exactly as the existing code.
- **1c.** In the same branch, apply ACL (`MatchACL`, same args as `handleStream`) and WebUI interceptor
  (`n.Interceptor.MatchAndHandle(payload, n.TAP)`) and `continue` when intercepted/blocked, matching
  `handleStream` ordering.

### 2. Fix config save (`pkg/config/config.go`, `pkg/web/server.go`, `pkg/web/interceptor.go`)
- **2a.** In `UpdateConfigFileDelta`, do not overwrite a mutable field when the incoming value is the
  zero value AND the field already exists in `rawMap` (treat zero as "not provided"). Apply to:
  `advertised_subnets`, `accept_advertised_subnets`, `allowed_subnet_peers`, `acl`. Keep current
  behavior for scalar fields the form always sends (node_name, strategy, psk, log_level, peers, mdns,
  obfuscation, exit_node, subnets flags) to avoid surprising behavior, but for the four fields above
  preserve on-disk value when incoming is empty/nil.
  *Alternative (preferred if WebUI always sends full config):* have both handlers merge from the
  current running `cfg` for omitted fields before calling `UpdateConfigFileDelta`. Pick one
  consistently. Recommend the merge-from-running-cfg approach in 2b.
- **2b.** In both `server.go` POST `/api/config` and `interceptor.go` POST `/api/config`: after
  decode, copy the running `cfg`'s current `AdvertisedSubnets`, `AcceptAdvertisedSubnets`,
  `AllowedSubnetPeers`, and `ACL` into `incoming` when the incoming value is empty, then update the
  running `cfg` with those four fields after the file write (so they take effect live).
- **2c.** Trigger live re-application: after updating `cfg`, if `AcceptAdvertisedSubnets`/subnets
  changed, re-run subnet route reconciliation (`processSubnetRoutes` for each peer in `peerMeta`).

### 3. Fix exit-node (`pkg/node/node.go`, `pkg/web/server.go`)
- **3a.** Create `node.SetExitNode(peerID, exitTapIP, endpoints)` wrapper (or call directly from
  WebUI) that, for action `set`, calls `n.Gateway.SetExitNode(...)` AND
  `n.NFTManager.EnableIPForwarding()` + `n.NFTManager.SetupExitNodeNAT(wanIf, tapName)` (mirroring
  `Start()`). For action `clear`, call `n.Gateway.ClearExitNode()` and
  `n.NFTManager.CleanupExitNodeNAT()`.
- **3b.** In `server.go` `/api/exitnode`, resolve physical P2P endpoint IPs (from the target peer's
  multiaddrs / `n.Host.Peerstore().Addrs`) and pass them as `endpoints` to `SetExitNode` instead of
  `nil`, so `ProtectEndpoint` installs loop-preventing host routes.
- **3c.** Make `SetExitNode` refuse (return error) when `GetOriginalPhysicalGateway()` fails AND no
  endpoints were supplied, instead of silently adding the default route with an empty gateway.

## Files to Edit
- `pkg/node/node.go` — relay handler (1a–1c), exit-node wrapper (3a), WebUI handler reuse (3b/3c).
- `pkg/config/config.go` — `UpdateConfigFileDelta` (2a).
- `pkg/web/server.go` — POST `/api/config` (2b/2c), `/api/exitnode` (3b/3c via 3a).
- `pkg/web/interceptor.go` — POST `/api/config` (2b/2c).
- `pkg/node/gateway.go` — `SetExitNode` guard (3c).

## Validation
- `go build ./...` and `go vet ./...`.
- Unit: `go test ./pkg/node/... ./pkg/switch/... ./pkg/config/...`.
- Existing `TestE2EBidirectionalIPv4AndIPv6Ping` and `TestE2EFullSuiteAfterInitialization` (these use
  direct P2P; extend or add a relayed variant by forcing a 3-node chain A→B→C where A↔C are not
  directly connected, then assert ICMP echo A→C and C→A succeed — this exercises 1a–1c).
- Manual: two peers connect; `ping <peer_tap_ip>` works both directions (covers A1–A3). Toggle
  exit-node from WebUI; verify `ip_forward=1` (Linux) / NAT table and default route appear, and
  `ping 8.8.8.8` from client egresses via exit node (covers C1–C3). Save config with only node_name
  changed; confirm `advertised_subnets`/ACL survive on disk and live (covers B1–B2).

## Risks / Notes
- Keep relay `handleRelayStream` symmetric with `handleStream` to avoid future divergence.
- Don't change the obfuscation/padding format (interop across peers).
- `nftables_others.go` stubs remain no-ops on Windows/macOS — document that runtime exit-node NAT is
  Linux-only; the wrapper must not error fatally on other OSes, just log.
