package evm

import (
	"errors"
	"fmt"
	"math/big"
)

// EIP-1559 transactions, for a wallet that sends USDC itself and pays its
// own gas: the fields, their RLP encoding and the signature. Only what a
// token transfer needs: an empty access list, no contract creation.
// Checked byte for byte against an independent signer (eth-account) in
// TestTx1559MatchesReference.

// Tx1559 is an EIP-1559 (type 2) transaction with an empty access list.
type Tx1559 struct {
	ChainID, Nonce              uint64
	MaxPriorityFee, MaxFee, Gas *big.Int
	To                          Address
	Value                       *big.Int
	Data                        []byte
}

func (t Tx1559) fields() []any {
	return []any{new(big.Int).SetUint64(t.ChainID), new(big.Int).SetUint64(t.Nonce), t.MaxPriorityFee, t.MaxFee, t.Gas,
		t.To[:], t.Value, t.Data, []any{}}
}

// SigningHash is what the signer signs: keccak256(0x02 || rlp(fields)).
func (t Tx1559) SigningHash() []byte {
	return Keccak256([]byte{0x02}, rlpEncode(t.fields()))
}

// Sign returns the raw transaction, 0x02 || rlp(fields, yParity, r, s), and
// its hash, which is the transaction's id on chain.
func (t Tx1559) Sign(s *EVMSigner) (raw, hash []byte, err error) {
	if t.MaxPriorityFee == nil || t.MaxFee == nil || t.Gas == nil || t.Value == nil {
		return nil, nil, errors.New("evm: a transaction needs its fees, gas and value")
	}
	sig, err := s.SignDigest(t.SigningHash()) // R || S || V, V = 27 + yParity
	if err != nil {
		return nil, nil, err
	}
	yParity := new(big.Int).SetUint64(uint64(sig[64] - 27))
	r, sv := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])
	raw = append([]byte{0x02}, rlpEncode(append(t.fields(), yParity, r, sv))...)
	return raw, Keccak256(raw), nil
}

// TransferData is the call data of an ERC-20 transfer(to, amount).
func TransferData(to Address, amount *big.Int) []byte {
	data := make([]byte, 4+32+32)
	copy(data, []byte{0xa9, 0x05, 0x9c, 0xbb}) // transfer(address,uint256)
	copy(data[4+12:], to[:])
	amount.FillBytes(data[4+32:])
	return data
}

// rlpEncode encodes byte strings, unsigned integers (*big.Int: minimal
// big-endian, zero as the empty string) and lists: all a transaction holds.
func rlpEncode(v any) []byte {
	switch x := v.(type) {
	case []byte:
		if len(x) == 1 && x[0] < 0x80 {
			return []byte{x[0]}
		}
		return append(rlpHead(0x80, len(x)), x...)
	case *big.Int:
		if x == nil || x.Sign() == 0 {
			return []byte{0x80}
		}
		return rlpEncode(x.Bytes())
	case []any:
		var body []byte
		for _, item := range x {
			body = append(body, rlpEncode(item)...)
		}
		return append(rlpHead(0xc0, len(body)), body...)
	}
	panic(fmt.Sprintf("rlp: %T", v))
}

func rlpHead(base byte, n int) []byte {
	if n < 56 {
		return []byte{base + byte(n)}
	}
	l := new(big.Int).SetInt64(int64(n)).Bytes()
	return append([]byte{base + 55 + byte(len(l))}, l...)
}
