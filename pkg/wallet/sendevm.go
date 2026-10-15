package wallet

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/pilot-protocol/wallet/pkg/evm"
)

// Sending USDC on chain, paying gas from this wallet's own ETH: the wallet
// signs a plain ERC-20 transfer as an EIP-1559 transaction and hands back
// the raw transaction for its host to broadcast. It never dials the chain
// itself, it only ever signs a transfer of its own USDC token, and every
// transfer counts against the same rolling spend cap as Pay and satisfy.

// TransferTx is what the host supplies to sign a transfer: where to, how
// much (in the token's smallest unit), and the chain's nonce, gas and fees
// for this wallet's address.
type TransferTx struct {
	To             evm.Address
	Amount         *big.Int
	Nonce          uint64
	Gas            *big.Int
	MaxFee         *big.Int // wei per gas
	MaxPriorityFee *big.Int // wei per gas
}

// Sanity limits on what a host may ask the wallet to pay in gas, so a
// caller cannot spend the wallet's ETH on absurd fees.
var (
	transferGasMax    = big.NewInt(200_000)
	transferMaxFeeMax = big.NewInt(100_000_000_000) // 100 gwei
)

// ErrBadTransfer is a transfer request the wallet will not sign.
var ErrBadTransfer = errors.New("wallet.evm.sign_transfer")

// SignUSDCTransferOn signs a USDC transfer from this wallet on chainID and
// returns the raw transaction and its hash.
func (w *Wallet) SignUSDCTransferOn(_ context.Context, chainID uint64, t TransferTx) (raw, hash []byte, err error) {
	b := w.evmByChain[chainID]
	if b == nil {
		return nil, nil, fmt.Errorf("%w: chain %d not configured", ErrBadTransfer, chainID)
	}
	switch {
	case t.To == evm.Address{}:
		return nil, nil, fmt.Errorf("%w: a recipient is required", ErrBadTransfer)
	case t.To == b.signer.Address():
		return nil, nil, fmt.Errorf("%w: that is this wallet's own address", ErrBadTransfer)
	case t.Amount == nil || t.Amount.Sign() <= 0 || !t.Amount.IsInt64():
		return nil, nil, fmt.Errorf("%w: the amount must be more than zero", ErrBadTransfer)
	case t.Gas == nil || t.Gas.Sign() <= 0 || t.Gas.Cmp(transferGasMax) > 0:
		return nil, nil, fmt.Errorf("%w: gas must be from 1 to %s", ErrBadTransfer, transferGasMax)
	case t.MaxFee == nil || t.MaxFee.Sign() <= 0 || t.MaxFee.Cmp(transferMaxFeeMax) > 0:
		return nil, nil, fmt.Errorf("%w: the fee per gas must be from 1 wei to 100 gwei", ErrBadTransfer)
	case t.MaxPriorityFee == nil || t.MaxPriorityFee.Sign() < 0 || t.MaxPriorityFee.Cmp(t.MaxFee) > 0:
		return nil, nil, fmt.Errorf("%w: the priority fee must be at most the fee per gas", ErrBadTransfer)
	}
	asset := NormalizeEVMAsset("USDC")
	amount := Amount(t.Amount.Int64())
	w.capMu.Lock()
	defer w.capMu.Unlock()
	if err := w.checkSpendCapLocked(asset, amount); err != nil {
		return nil, nil, err
	}
	tx := evm.Tx1559{ChainID: chainID, Nonce: t.Nonce, MaxPriorityFee: t.MaxPriorityFee, MaxFee: t.MaxFee, Gas: t.Gas,
		To: b.method.Token(), Value: big.NewInt(0), Data: evm.TransferData(t.To, t.Amount)}
	raw, hash, err = tx.Sign(b.signer)
	if err != nil {
		return nil, nil, err
	}
	w.recordSpendLocked(asset, amount)
	return raw, hash, nil
}
