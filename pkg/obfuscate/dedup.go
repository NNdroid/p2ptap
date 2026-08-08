package obfuscate

import "sync"

// Deduplicator tracks received Sequence IDs to discard duplicates in 'redundant' strategy.
type Deduplicator struct {
	mu           sync.Mutex
	maxSeq       uint64
	receivedBits [WindowSizeBitmask]bool
}

// NewDeduplicator creates a new Deduplicator.
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{}
}

// IsDuplicate returns true if the seqID has already been received,
// otherwise records it and returns false.
func (d *Deduplicator) IsDuplicate(seqID uint64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if seqID == 0 {
		return false
	}

	if seqID > d.maxSeq {
		diff := seqID - d.maxSeq
		if diff >= WindowSizeBitmask {
			// Clear all — window jumped too far
			log.Debug("Dedup: window reset, old max=%d new=%d (jump=%d)", d.maxSeq, seqID, diff)
			for i := range d.receivedBits {
				d.receivedBits[i] = false
			}
		} else {
			// Shift window forward
			for i := uint64(0); i < diff; i++ {
				idx := (d.maxSeq + 1 + i) % WindowSizeBitmask
				d.receivedBits[idx] = false
			}
		}
		d.maxSeq = seqID
		idx := seqID % WindowSizeBitmask
		d.receivedBits[idx] = true
		return false
	}

	// seqID <= maxSeq
	if d.maxSeq-seqID >= WindowSizeBitmask {
		// Too old — outside dedup window
		log.Debug("Dedup: seq=%d too old (max=%d, diff=%d), dropped", seqID, d.maxSeq, d.maxSeq-seqID)
		return true
	}

	idx := seqID % WindowSizeBitmask
	if d.receivedBits[idx] {
		return true
	}
	d.receivedBits[idx] = true
	return false
}
