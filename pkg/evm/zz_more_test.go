package evm

import (
	"errors"
	"testing"
)

func TestErrUnknownChain_ChainID(t *testing.T) {
	t.Parallel()
	err := errChainUnknown(31337)
	if err.Error() == "" {
		t.Error("error message empty")
	}
	var uc errUnknownChain
	if !errors.As(err, &uc) {
		t.Fatal("errors.As failed")
	}
	if uc.ChainID() != 31337 {
		t.Errorf("ChainID = %d, want 31337", uc.ChainID())
	}
}

func TestEVMSigner_PublicKey(t *testing.T) {
	t.Parallel()
	s, err := NewEVMSigner()
	if err != nil {
		t.Fatalf("NewEVMSigner: %v", err)
	}
	pub := s.PublicKey()
	if len(pub) != 65 {
		t.Errorf("PublicKey len = %d, want 65 (uncompressed)", len(pub))
	}
	if pub[0] != 0x04 {
		t.Errorf("PublicKey[0] = %#x, want 0x04 prefix", pub[0])
	}
}

func TestEVMSigner_AddressAndPrivateKeyBytes(t *testing.T) {
	t.Parallel()
	s, err := NewEVMSigner()
	if err != nil {
		t.Fatalf("NewEVMSigner: %v", err)
	}
	if (s.Address() == Address{}) {
		t.Error("Address is zero")
	}
	if len(s.PrivateKeyBytes()) != 32 {
		t.Errorf("PrivateKeyBytes len = %d, want 32", len(s.PrivateKeyBytes()))
	}
}
