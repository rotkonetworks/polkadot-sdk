// Copyright (C) Rotko Networks OÜ.
// SPDX-License-Identifier: Apache-2.0

//! Integration guide for held transaction queue.
//!
//! The `HeldTransactionQueue` holds transactions privately until block building time,
//! then flushes them to the pool with `TransactionSource::Local` priority.
//!
//! # Security Model
//!
//! Unlike `author_submitExtrinsic` which puts transactions in the pool where they are:
//! - Visible via `author_pendingExtrinsics` RPC
//! - Gossiped to other nodes (unless using `--reserved-only`)
//!
//! Transactions in the held queue are:
//! - NOT visible via `author_pendingExtrinsics`
//! - NOT in the pool until just before block building
//! - Flushed with `TransactionSource::Local` for highest priority
//!
//! Combined with `--reserved-only --reserved-nodes ""` network isolation, this
//! prevents attackers from seeing transactions before inclusion.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐     ┌───────────────────┐     ┌──────────────────┐
//! │  RPC Layer   │────▶│ HeldTransactionQ  │────▶│  Transaction     │
//! │ submitHeld() │     │   (private queue) │     │     Pool         │
//! └──────────────┘     └───────────────────┘     └──────────────────┘
//!                            │                          │
//!                            │ (flush at block build)   │
//!                            └──────────────────────────┘
//!                                                       │
//!                                                       ▼
//!                                              ┌──────────────────┐
//!                                              │     Proposer     │
//!                                              │  (builds block)  │
//!                                              └──────────────────┘
//! ```
//!
//! # Components
//!
//! 1. **HeldTransactionQueue** (`sc-held-transactions`): Private transaction storage
//! 2. **HeldTransactionRpc** (`polkadot-omni-node-lib::common::held`): RPC endpoint
//! 3. **CollatorWithHeldQueue** (`cumulus-client-consensus-aura::collator`): Collator wrapper
//!
//! # Usage
//!
//! ```ignore
//! // 1. Create shared queue
//! let held_queue = HeldTransactionQueue::<Block>::new();
//!
//! // 2. Pass to RPC
//! let rpc = HeldTransactionRpc::new(held_queue.clone());
//!
//! // 3. Pass to collator
//! let collator = CollatorWithHeldQueue::new(ParamsWithHeldQueue {
//!     base: collator_params,
//!     held_queue,
//!     transaction_pool: pool,
//! });
//!
//! // 4. When collator's slot arrives and collate() is called:
//! //    - held queue is drained
//! //    - txs are submitted to pool with Local priority
//! //    - proposer builds block (including the held txs)
//! ```
//!
//! # Use Case: Recovery from Compromised Accounts
//!
//! When sweeper bots monitor an account for incoming funds:
//!
//! 1. Build rescue transaction offline (rebond, transfer, etc.)
//! 2. Run collator with:
//!    - `--reserved-only --reserved-nodes ""` (no gossip)
//!    - `--rpc-methods unsafe` (enable held RPC)
//! 3. Submit via `author_submitHeld` RPC
//! 4. Transaction stays invisible until collator's slot
//! 5. When slot arrives, tx is flushed and included in block
//! 6. Attacker never sees the transaction before inclusion
