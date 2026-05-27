// SPDX-License-Identifier: AGPL-3.0-or-later

package evm

// Regression for the typo-loss vector: ParseAddress accepts any 20-byte
// hex without checksum validation. A user copy-pasting an EVM address
// with a one-character typo (e.g., from a phishing site, or just human
// error) would have it silently accepted and lose funds on send.
//
// Fix: EIP-55 checksum validation. Mixed-case input MUST match the
// EIP-55 canonical form. All-lowercase and all-uppercase remain
// accepted (they convey no checksum information — wallets that don't
// emit checksummed addresses can still interoperate).

import (
	"strings"
	"testing"
)

func TestParseAddressRejectsBadEIP55Checksum(t *testing.T) {
	t.Parallel()

	// Vitalik's well-known address. The canonical EIP-55 form is:
	//   0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
	// We tamper with ONE letter's case (the leading 'd' should be 'd',
	// flip it to 'D') to produce an invalid checksum. Bytes are
	// identical to the canonical form; only the case is wrong.
	const canonical = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
	tampered := "0x" + "D" + canonical[3:]

	// Canonical: must accept.
	if _, err := ParseAddress(canonical); err != nil {
		t.Fatalf("canonical EIP-55 address rejected: %v", err)
	}

	// Tampered: must reject.
	_, err := ParseAddress(tampered)
	if err == nil {
		t.Fatalf("tampered checksum accepted — typo-loss vector still open. Input: %q", tampered)
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("expected error to mention 'checksum', got: %v", err)
	}
}

func TestParseAddressAcceptsAllLowerOrAllUpper(t *testing.T) {
	t.Parallel()
	// Strings with NO case mix carry no checksum signal — accept them.
	// This preserves compatibility with wallets that don't emit
	// checksummed addresses (older clients, some hardware wallets).

	cases := []string{
		"0xd8da6bf26964af9d7eed9e03e53415d37aa96045", // all lower
		"0xD8DA6BF26964AF9D7EED9E03E53415D37AA96045", // all upper
	}
	for _, in := range cases {
		if _, err := ParseAddress(in); err != nil {
			t.Errorf("ParseAddress(%q) returned error: %v", in, err)
		}
	}
}

func TestParseAddressNoPrefix(t *testing.T) {
	t.Parallel()
	// Bare hex (no 0x prefix) preserved for backwards-compat. Mixed
	// case STILL gets checksum-checked if present.

	if _, err := ParseAddress("d8da6bf26964af9d7eed9e03e53415d37aa96045"); err != nil {
		t.Errorf("bare-hex lowercase rejected: %v", err)
	}
}
