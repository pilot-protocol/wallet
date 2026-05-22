package evm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// EIP-3009 transferWithAuthorization is the x402 settlement primitive.
// A payer signs a typed-data structure binding (from, to, value,
// validAfter, validBefore, nonce). The signed authorization travels
// out-of-band (HTTP 402 body, pilot SealedEnvelope, anywhere); a
// recipient submits it to the token contract via
// transferWithAuthorization(...), which checks the EIP-712 signature
// and moves `value` tokens from `from` to `to`.
//
// References:
//   - EIP-3009 transferWithAuthorization
//   - EIP-712 typed data hashing
//   - x402 protocol (HTTP 402 + EIP-3009)
//
// Standard contract source of truth for this on USDC.

// TransferAuth is the structured data that gets signed. Field order
// matches the EIP-3009 spec exactly — re-ordering changes the
// type-hash and breaks signature compatibility with on-chain contracts.
type TransferAuth struct {
	From        Address
	To          Address
	Value       *big.Int
	ValidAfter  *big.Int
	ValidBefore *big.Int
	Nonce       [32]byte
}

// TransferWithAuthorizationTypeHash is keccak256 of the EIP-712 type
// string for TransferWithAuthorization. Standard constant — every
// EIP-3009 contract on every chain computes the same value.
//
//	keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
var TransferWithAuthorizationTypeHash = Keccak256(
	[]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"),
)

// EIP712DomainTypeHash is keccak256 of the standard EIP-712 domain
// type string. Same for every EIP-712 contract.
var EIP712DomainTypeHash = Keccak256(
	[]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
)

// Domain identifies which on-chain contract+chain the authorization
// targets. Two authorizations with the same fields but different
// Domains produce different signatures — that's the whole point of
// domain separation in EIP-712.
type Domain struct {
	Name              string  // e.g. "USD Coin"
	Version           string  // e.g. "2"
	ChainID           uint64  // 8453 = Base mainnet, 84532 = Base Sepolia, 1 = Ethereum mainnet
	VerifyingContract Address // the token contract's address
}

// DomainSeparator returns keccak256(EIP712DomainTypeHash || keccak256(name)
// || keccak256(version) || abi.encode(uint256 chainId) || abi.encode(address contract)).
// Standard EIP-712 construction.
func (d Domain) Separator() []byte {
	nameHash := Keccak256([]byte(d.Name))
	versionHash := Keccak256([]byte(d.Version))
	chainIDBytes := abiUint256(new(big.Int).SetUint64(d.ChainID))
	verifyingContractBytes := abiAddress(d.VerifyingContract)
	return Keccak256(
		EIP712DomainTypeHash,
		nameHash,
		versionHash,
		chainIDBytes,
		verifyingContractBytes,
	)
}

// StructHash returns keccak256(typeHash || encoded fields) for a
// TransferAuth — the inner half of an EIP-712 signing input.
func (t TransferAuth) StructHash() []byte {
	return Keccak256(
		TransferWithAuthorizationTypeHash,
		abiAddress(t.From),
		abiAddress(t.To),
		abiUint256(t.Value),
		abiUint256(t.ValidAfter),
		abiUint256(t.ValidBefore),
		t.Nonce[:],
	)
}

// EIP3009Digest returns the 32-byte digest the payer signs. Per EIP-712:
//
//	digest = keccak256(0x19 0x01 || domainSeparator || structHash)
//
// The signature produced over this digest is what the on-chain
// transferWithAuthorization function will accept.
func EIP3009Digest(domain Domain, auth TransferAuth) []byte {
	return Keccak256(
		[]byte{0x19, 0x01},
		domain.Separator(),
		auth.StructHash(),
	)
}

// SignTransferAuth is a convenience wrapper: derive the EIP-712 digest
// for (domain, auth), sign it, return the 65-byte R||S||V signature
// that on-chain transferWithAuthorization callers expect to split into
// (v, r, s).
func (s *EVMSigner) SignTransferAuth(domain Domain, auth TransferAuth) ([]byte, error) {
	if auth.From != s.addr {
		return nil, fmt.Errorf("evm: signing as %s but auth.From=%s", s.addr, auth.From)
	}
	digest := EIP3009Digest(domain, auth)
	return s.SignDigest(digest)
}

// VerifyTransferAuth recovers the signer from a signature over the
// (domain, auth) EIP-712 digest and confirms it matches auth.From.
// Returns nil on a valid pair, an error otherwise. This is what the
// platform's receiver side does before deciding to submit the
// authorization on-chain — saves the on-chain gas cost of a broken
// signature.
func VerifyTransferAuth(domain Domain, auth TransferAuth, signature []byte) error {
	if auth.Value == nil || auth.ValidAfter == nil || auth.ValidBefore == nil {
		return errors.New("evm: nil bigint in TransferAuth")
	}
	digest := EIP3009Digest(domain, auth)
	recovered, err := Recover(digest, signature)
	if err != nil {
		return fmt.Errorf("evm: verify recover: %w", err)
	}
	if recovered != auth.From {
		return fmt.Errorf("evm: signature is from %s, claimed from %s", recovered, auth.From)
	}
	return nil
}

// ── ABI encoding primitives (just what we need for EIP-712) ─────────────

// abiUint256 left-pads a uint256 to 32 bytes (big-endian, ABI standard).
func abiUint256(n *big.Int) []byte {
	if n == nil {
		return make([]byte, 32)
	}
	b := n.Bytes()
	if len(b) > 32 {
		// Negative or oversized — we don't support; return a defensive zero.
		return make([]byte, 32)
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// abiAddress encodes a 20-byte address as a 32-byte ABI-padded slot.
func abiAddress(a Address) []byte {
	out := make([]byte, 32)
	copy(out[12:], a[:])
	return out
}

// Uint64 is a small helper to encode timestamps as *big.Int for the
// ValidAfter / ValidBefore fields without leaving Uint conversions
// littering caller code.
func Uint64(n uint64) *big.Int { return new(big.Int).SetUint64(n) }

// Uint128 packs a uint64 high and uint64 low into a single big.Int —
// rarely needed (USDC amounts fit in 64 bits comfortably) but provided
// for completeness when callers want explicit 128-bit values.
func Uint128(hi, lo uint64) *big.Int {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], hi)
	binary.BigEndian.PutUint64(buf[8:], lo)
	return new(big.Int).SetBytes(buf[:])
}
