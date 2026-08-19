package version

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
)

// These variables are injected at compile time via -ldflags
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// EnvelopeVersion is the wire-format version of the relay / boot-relay envelope
// framing. It is exchanged during the PSK auth handshake so a node and a boot
// running MISMATCHED envelope layouts are rejected up-front instead of silently
// corrupting relayed frames (the historical 0x8000 "proto field len 32768"
// truncation class of bug). Bump this whenever pkg/routing relay envelope
// encoding changes in a non-backward-compatible way.
const EnvelopeVersion uint8 = 1

// StrictVersionCheck controls whether a DANGER-level version mismatch (relay
// envelope wire formats with NO common version) hard-rejects the auth
// connection (true) or merely logs loudly and allows it (false).
//
// Default is FALSE: mismatches are WARN/ERROR-logged but the connection is
// allowed, so two peers that CAN interoperate are never blocked. A plain commit
// difference with an identical envelope is always safe and only warned. Only an
// genuinely incompatible envelope (no common version) escalates to DANGER, and
// even that is allowed unless an operator explicitly opts into hard rejection by
// setting StrictVersionCheck=true (e.g. a high-security deployment that prefers
// losing a link over risking silent relay-frame corruption).
var StrictVersionCheck = false

// CompatLevel classifies the outcome of a version / envelope capability check.
// It is a TRI-STATE rather than a boolean because a mismatch is almost never an
// absolute "cannot connect" — it is a matter of HOW SAFE the connection is.
type CompatLevel int

const (
	CompatOK     CompatLevel = iota // identical build, or unknown (old) peer — safe
	CompatWarn                      // builds differ but wire format safe — log & allow
	CompatDanger                    // envelope formats incompatible — corruption risk
)

func (c CompatLevel) String() string {
	switch c {
	case CompatOK:
		return "ok"
	case CompatWarn:
		return "warn"
	case CompatDanger:
		return "danger"
	default:
		return "unknown"
	}
}

// supportedEnvelopes is the set of relay / boot-relay envelope wire versions this
// build can speak, ordered by preference (highest first). Today only v1 exists;
// listing a SET (rather than a single version) lets the auth handshake NEGOTIATE
// the highest common version with a peer instead of blindly rejecting on mismatch
// — the standard TLS/ALPN-style capability negotiation.
var supportedEnvelopes = []uint8{EnvelopeVersion}

func Full() string {
	return fmt.Sprintf("p2ptap %s (commit: %s, built: %s, %s/%s, %s)",
		Version, short(GitCommit, 9), BuildTime, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func Short() string {
	return fmt.Sprintf("p2ptap %s", Version)
}

// ShortCommit returns the truncated GitCommit for compact logging.
func ShortCommit() string {
	return short(GitCommit, 9)
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Record is the version / capability blob exchanged on the PSK auth handshake.
// It is length-prefixed (2 bytes) so an OLD peer that sends none is detected by
// a short read rather than a parse error.
type Record struct {
	Version   string   `json:"v"`            // human version string (e.g. "dev", "1.2.3")
	Commit    string   `json:"c"`            // GitCommit injected at build time
	Envelope  uint8    `json:"e"`            // preferred wire envelope version (EnvelopeVersion)
	Envelopes []uint8  `json:"ev,omitempty"` // set of envelope versions supported (negotiation)
}

// CurrentRecord returns the local node/boot's version Record.
func CurrentRecord() Record {
	return Record{Version: Version, Commit: GitCommit, Envelope: EnvelopeVersion, Envelopes: supportedEnvelopes}
}

// WriteRecord writes a 2-byte length-prefixed JSON record to w. (Named
// WriteRecord rather than WriteTo to avoid colliding with the io.WriterTo
// interface signature that vet enforces.)
func (r Record) WriteRecord(w io.Writer) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(b)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// ReadRecord reads a 2-byte length-prefixed JSON record from rd. It returns
// io.EOF / io.ErrUnexpectedEOF (or any short-read error) when the peer sent no
// record at all (an OLD build) — callers treat that as "unknown version" and
// allow, possibly with a warning, rather than failing the whole handshake.
func (r *Record) ReadRecord(rd io.Reader) error {
	var lenBuf [2]byte
	if _, err := io.ReadFull(rd, lenBuf[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 {
		return errors.New("empty version record")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(rd, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, r)
}

// known reports whether the record carries a usable commit (false for an old
// build whose commit string is empty or the compile-time "unknown" placeholder).
func (r Record) known() bool {
	return r.Commit != "" && r.Commit != "unknown"
}

// CompatibleWith assesses compatibility with a peer record and returns a level
// plus a human-readable reason. It NEVER unconditionally rejects: the caller
// decides whether to hard-reject on CompatDanger (only when StrictVersionCheck
// is enabled). Levels:
//   - CompatOK:     identical build, or peer version unknown (old build) — safe.
//   - CompatWarn:   builds differ but the relay envelope wire format is safe to
//                   use (same envelope, OR a common version was negotiated) — log
//                   and allow.
//   - CompatDanger: envelope wire formats are incompatible with NO common version
//                   — connecting risks silent relay-frame corruption. Log loudly;
//                   reject only if StrictVersionCheck is on.
func (r Record) CompatibleWith(peer Record) (CompatLevel, string) {
	// Unknown peer (old build) — cannot verify, allow but note. The node/boot
	// side already warned on the short read; this keeps a single upgraded side
	// from hard-breaking a fleet still on old code.
	if !r.known() || !peer.known() {
		return CompatOK, "peer version unknown (old build) — cannot verify envelope compatibility"
	}
	if r.Commit == peer.Commit {
		return CompatOK, ""
	}
	// Same envelope wire version: the build differs but the relay framing is
	// byte-for-byte compatible. Common "rebuilt with same layout" case — connect
	// freely, just note it.
	if r.Envelope == peer.Envelope {
		return CompatWarn, fmt.Sprintf("commit differs (local=%s peer=%s) but relay envelope v%d is identical — safe to connect",
			short(r.Commit, 9), short(peer.Commit, 9), r.Envelope)
	}
	// Envelope differs: try to negotiate a common version. If we can, downgrade
	// to that shared format and connect safely (warn only).
	if ver, ok := r.NegotiateEnvelope(peer); ok {
		return CompatWarn, fmt.Sprintf("envelope versions differ (local=%d peer=%d) but negotiated common v%d — connecting with that format",
			r.Envelope, peer.Envelope, ver)
	}
	// No common envelope version at all: any relay frame would be silently
	// corrupted (the historical 0x8000 class of bug). Loud error; the caller may
	// reject only when StrictVersionCheck is enabled.
	return CompatDanger, fmt.Sprintf("relay envelope wire versions incompatible (local=%d peer=%d, no common version) — risk of silent relay-frame corruption",
		r.Envelope, peer.Envelope)
}

// NegotiateEnvelope returns the highest envelope wire version both sides support,
// or (0, false) if there is no overlap (a genuine corruption risk). Either side
// may omit the Envelopes list (old build) in which case its single Envelope field
// is treated as its only supported version.
func (r Record) NegotiateEnvelope(peer Record) (uint8, bool) {
	mine := r.Envelopes
	if len(mine) == 0 {
		mine = []uint8{r.Envelope}
	}
	theirs := peer.Envelopes
	if len(theirs) == 0 {
		theirs = []uint8{peer.Envelope}
	}
	have := make(map[uint8]struct{}, len(theirs))
	for _, v := range theirs {
		have[v] = struct{}{}
	}
	// mine is preference-ordered (highest first), so the first common entry is
	// the highest common version.
	var best uint8
	found := false
	for _, v := range mine {
		if _, ok := have[v]; ok {
			best = v
			found = true
			break
		}
	}
	return best, found
}
