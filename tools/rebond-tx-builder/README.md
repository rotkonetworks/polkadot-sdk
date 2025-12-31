# rebond-tx-builder

build and verify signed staking.rebond transactions for asset hub recovery operations.

designed to work with network-isolated cumulus collators to bypass mempool visibility and front-running attacks.

## the problem

when an account is compromised, attackers run sweeper bots watching the mempool. any incoming funds or recovery attempts are immediately front-run and drained.

## the solution

1. victim builds signed transactions offline (this tool)
2. trusted collator runs with network isolation (no tx gossip)
3. submit tx to collator's local RPC just before authoring slot
4. attacker never sees tx until it's already in a finalized block

## usage

### step 1: victim builds transactions

```bash
# basic rebond (nonces auto-fetched from default rpc)
./rebond-tx-builder \
  --seed "victim mnemonic phrase here" \
  --rebond-amount 188932 \
  -o recovery.txt

# with funding tx for fees (nonces auto-fetched)
./rebond-tx-builder \
  --seed "victim mnemonic" \
  --rebond-amount 188932 \
  --funder-seed "funder mnemonic" \
  --fund-amount 0.1 \
  -o recovery.txt

# manual nonces (offline mode)
./rebond-tx-builder \
  --seed "victim mnemonic" \
  --rebond-amount 188932 \
  --victim-nonce 5 \
  -o recovery.txt
```

default rpc endpoints (auto-used per network):
- polkadot asset hub: `https://asset-hub-polkadot.dotters.network`
- kusama asset hub: `https://asset-hub-kusama.dotters.network`

override with `--rpc <url>` if needed.

output file contains:
- transaction hex
- intent description
- verify command for collator

### step 2: collator verifies transactions

before loading any tx, collator must verify:

```bash
./rebond-tx-builder --verify 0x<hex_from_victim>
```

output shows:
- signer address (confirm it's the victim)
- call decoded (confirm it's staking.rebond with correct amount)
- signature validity (cryptographic verification)

example:
```
══════════════════════════════════════════════════════════════════
  transaction verification
══════════════════════════════════════════════════════════════════

  signer:         14Gjs1TD93...
  call data:
    pallet index: 80
    call index:   19
    decoded:      staking.rebond(188932 DOT)

  ✓ this is a rebond transaction

  signature verification:
    ✓ signature valid

  ══════════════════════════════════════════════════════════════
  ✓ VERIFIED: transaction is correctly signed by 14Gjs1TD93...
  ══════════════════════════════════════════════════════════════
```

### step 3: collator submits to local node

run collator with network isolation to prevent gossip:

```bash
polkadot-parachain \
  --chain=asset-hub-polkadot \
  --collator \
  --reserved-only \
  --reserved-nodes "" \
  --rpc-methods unsafe \
  # ... other flags
```

**what `--reserved-only` does:**
- only connects to explicitly listed reserved nodes
- with empty `--reserved-nodes ""`, connects to NO peers
- transactions in pool are never gossiped (no peers to gossip to)
- still syncs via relay chain (collator gets blocks from validators)

**downsides of network isolation:**
- slower block propagation (no p2p gossip, only via relay chain)
- your blocks will be empty except for your submitted txs (you don't see network txs)
- no fallback if relay chain has issues
- not contributing to network health

**recommendation:** only run isolated temporarily for recovery, switch back to normal after your tx is finalized

submit tx with highest priority just before your slot:

```bash
# option 1: author_submitLocal (highest priority, requires --rpc-methods unsafe)
curl -X POST http://localhost:9944 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"author_submitLocal","params":["0x<tx_hex>"]}'

# option 2: standard author_submitExtrinsic (also works with isolation)
curl -X POST http://localhost:9944 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"author_submitExtrinsic","params":["0x<tx_hex>"]}'
```

`author_submitLocal` uses `TransactionSource::Local` which has higher pool priority than `External`.

### step 4: wait for authoring slot

asset hub uses aura consensus with round-robin slots:
```
your_slot = (current_slot % num_collators) == your_index
```

**key timing:**
- calculate when your slot will occur
- submit tx 1-2 seconds before your slot
- tx stays in local pool only (no peers to gossip to)
- your block includes the tx before anyone sees it

## timing considerations

- asset hub slot time: ~6 seconds
- number of collators: check on-chain
- worst case wait: num_collators * 6 seconds

for time-sensitive recovery:
- coordinate with multiple trusted collators
- reduces average wait time
- increases success probability

## network presets

```bash
# polkadot asset hub (default)
--network polkadot-asset-hub

# kusama asset hub
--network kusama-asset-hub

# custom network (requires genesis hash)
--network custom --genesis-hash <hex>
```

## nonce handling

nonces are auto-fetched from rpc by default. for offline mode or custom nonces:

```bash
--victim-nonce 5
--funder-nonce 0
```

if tx fails with "nonce too low", rebuild with updated nonce (or let auto-fetch get latest).

## security notes

- never share seed phrases over unencrypted channels
- verify tx hex before loading (collator responsibility)
- only use trusted collators operated by known entities
- `author_submitLocal` requires `--rpc-methods unsafe` flag

## building from source

```bash
cd tools/rebond-tx-builder
cargo build --release
./target/release/rebond-tx-builder --help
```

## related components

- `cumulus/polkadot-omni-node/lib/src/common/held.rs` - LocalTransactionRpc implementation
