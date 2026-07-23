// SPDX-License-Identifier: AGPL-3.0-or-later

package settlerclient

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// randomNonce returns 16 random bytes. The settler's nonce dedupe
// table is keyed on the hex string, so any high-entropy 16-byte
// value works. 128 bits ≫ birthday paradox over realistic transfer
// volumes.
func randomNonce() ([]byte, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("settler client: nonce: %w", err)
	}
	return b[:], nil
}

// newReqID returns a short opaque request id for envelope tagging.
// The server echoes it back; the client doesn't track it across
// requests (one connection = one request), so any unique value
// works.
func newReqID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
