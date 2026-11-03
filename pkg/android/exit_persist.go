package P2PTap

import (
	"errors"
	"os"
	"strings"
)

// exitSelectionFile is the app-private file that remembers which peer the user
// selected as the Exit Node.
//
// It exists because the selection has to outlive the process. The engine holds
// the active Exit Node only in GatewayManager memory and drops it on every
// Stop(), while the app UI keeps showing the peer the user picked. Without a
// durable record, Start() comes back with NO exit node while the app still
// reports "enabled": the phone routes everything into the TUN device, the node
// has nowhere to send it (no exit peer, and on Android every frame leaves the
// TUN with a broadcast destination MAC so L2 discovery cannot help either), and
// the user sees a VPN that is connected and completely dead.
//
// The file is deliberately not part of config.json: the Exit Node is a runtime
// selection per device, not a property of the node's identity, and folding it
// into the config schema would make every device that ever selected an exit
// node rewrite its config file.
const exitSelectionFile = "exit_node_peer"

// saveExitSelection records peerID as the persistent Exit Node choice. An empty
// peerID clears the record. Relative state paths resolve under the app's private
// storage via resolveStatePath, so the caller only ever names the file.
func saveExitSelection(peerID string) error {
	peerID = strings.TrimSpace(peerID)
	p := resolveStatePath(exitSelectionFile)
	if peerID == "" {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return os.WriteFile(p, []byte(peerID+"\n"), 0o600)
}

// loadExitSelection returns the persisted Exit Node peer ID, or "" when none was
// ever saved. Every failure mode (missing file, unreadable directory, empty
// content) degrades to "no selection": a broken state file must never keep the
// tunnel from starting.
func loadExitSelection() string {
	data, err := os.ReadFile(resolveStatePath(exitSelectionFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// exitSelectionFilePath is the resolved location, for diagnostics only.
func exitSelectionFilePath() string {
	return resolveStatePath(exitSelectionFile)
}
