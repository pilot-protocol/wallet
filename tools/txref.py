# Prints the reference raw transaction for pkg/evm/tx_test.go, signed by an
# independent implementation (eth-account), so the Go signer is checked
# against it:
#
#   TX_REFERENCE=$(uv run -q --with eth-account==0.13.4 python tools/txref.py) go test ./pkg/evm/
from eth_account import Account

KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'  # Hardhat's first test key
USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
PAYEE = '0x70997970c51812dc3a010c7d01b50e0d17dc79c8'

selector = bytes.fromhex('a9059cbb')  # transfer(address,uint256)
data = selector + bytes(12) + bytes.fromhex(PAYEE[2:]) + (250000).to_bytes(32, 'big')
tx = {'type': 2, 'chainId': 8453, 'nonce': 7, 'maxPriorityFeePerGas': 1_000_000, 'maxFeePerGas': 50_000_000,
      'gas': 80_000, 'to': USDC_BASE, 'value': 0, 'data': '0x' + data.hex(), 'accessList': []}
print('0x' + Account.sign_transaction(tx, KEY).raw_transaction.hex().removeprefix('0x'))
