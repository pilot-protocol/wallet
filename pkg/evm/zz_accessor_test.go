package evm

import (
	"testing"
)

// TestEVMMethod_AccessorsCoverIDChainTokenAddress hits the four tiny
// accessor functions on *EVMMethod that don't go through Satisfy/Verify
// and previously had 0% coverage.
func TestEVMMethod_AccessorsCoverIDChainTokenAddress(t *testing.T) {
	t.Parallel()
	s, err := NewEVMSigner()
	if err != nil {
		t.Fatalf("NewEVMSigner: %v", err)
	}
	m, err := NewEVMMethod(s, ChainBaseSepolia, nil)
	if err != nil {
		t.Fatalf("NewEVMMethod: %v", err)
	}
	if got := m.ID(); got != EVMMethodID {
		t.Errorf("ID = %q, want %q", got, EVMMethodID)
	}
	if got := m.ChainID(); got != ChainBaseSepolia {
		t.Errorf("ChainID = %d, want %d", got, ChainBaseSepolia)
	}
	zero := Address{}
	if m.Token() == zero {
		t.Error("Token is zero — expected canonical USDC default for chain")
	}
	if m.Address() == zero {
		t.Error("Address is zero")
	}
}

// TestClient_EndpointReturnsConfigured covers the Endpoint accessor
// previously at 0%.
func TestClient_EndpointReturnsConfigured(t *testing.T) {
	t.Parallel()
	c := NewClient("https://example.invalid/rpc", nil)
	if c.Endpoint() != "https://example.invalid/rpc" {
		t.Errorf("Endpoint = %q", c.Endpoint())
	}
}

// TestNewClient_NilHTTPClientGetsDefault covers the nil-client branch.
func TestNewClient_NilHTTPClientGetsDefault(t *testing.T) {
	t.Parallel()
	c := NewClient("https://example.invalid", nil)
	if c.http == nil {
		t.Error("http client should be non-nil after NewClient(_, nil)")
	}
}

// TestUint128_PacksHiLo covers the Uint128 helper used in EIP-3009
// encoding — previously 0% because no test ever called it.
func TestUint128_PacksHiLo(t *testing.T) {
	t.Parallel()
	// hi=0, lo=1 → 1
	if got := Uint128(0, 1); got.Uint64() != 1 {
		t.Errorf("Uint128(0,1) = %s, want 1", got.String())
	}
	// hi=1, lo=0 → 2^64
	got := Uint128(1, 0)
	want := "18446744073709551616" // 2^64
	if got.String() != want {
		t.Errorf("Uint128(1,0) = %s, want %s", got.String(), want)
	}
}
