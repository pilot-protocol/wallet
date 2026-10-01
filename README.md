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

## Release

Pushing a `v*` tag runs `.github/workflows/release.yml`:

1. Tests.
2. A native `CGO_ENABLED=0` build on linux/amd64, linux/arm64, darwin/amd64 and darwin/arm64. The job checks each binary's `file` output and requires `wallet -version` to equal the tag.
3. The binary's sha256 is pinned into `manifest.json`, which is signed with the `PILOT_APP_PUBLISHER_KEY` repo secret (public key `ed25519:VF8fdEP/Oe2aWN3ozQ7Ar22137tHb7dkSw0hlzlk/os=`, the catalogue's publisher pin for `io.pilot.wallet`).
4. Each platform is packed as `io.pilot.wallet-<version>-<os>-<arch>.tar.gz` by `scripts/pack-bundle.py`.
5. The four bundles are published with `checksums.txt` and build provenance.

The catalogue entry (pilot-protocol/pilotprotocol `catalogue/catalogue.json`) then gets a `bundles` map with one entry per platform, built from those URLs and checksums. The `Version` constant in `cmd/wallet` and `app_version` in `manifest.json` must equal the tag.
