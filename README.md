# wallet

[![ci](https://github.com/pilot-protocol/wallet/actions/workflows/ci.yml/badge.svg)](https://github.com/pilot-protocol/wallet/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pilot-protocol/wallet/branch/main/graph/badge.svg)](https://codecov.io/gh/pilot-protocol/wallet)

Wallet primitives for the Pilot Protocol: Ed25519 keypairs (the daemon identity) and EVM secp256k1 keys (for on-chain payments / signed receipts).

## Packages

- `pkg/wallet` — local Ed25519 signer; reads / writes `identity.json` with mode 0600 + (since the May 2026 audit sweep) emits a warning when an existing file is mode 0644 or looser.
- `pkg/evm` — secp256k1 signer; ParseAddress enforces EIP-55 checksum on mixed-case input; cross-chain replay protection via EIP-712 domain separation.
- `cmd/wallet` — CLI for generating / inspecting wallets.

## Test

```bash
go test -race -coverprofile=coverage.out -covermode=atomic ./...
```
