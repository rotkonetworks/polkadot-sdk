// Copyright (C) Rotko Networks OÜ.
// SPDX-License-Identifier: Apache-2.0

//! Held transaction queue for slot-aware block building.
//!
//! This module provides a queue for transactions that should be held until the
//! collator's slot arrives, then injected directly into the block without
//! going through the normal transaction pool (and thus avoiding gossip).
//!
//! # Use Case
//!
//! This is useful for scenarios where you want to submit transactions that:
//! - Should not be gossiped to other nodes before inclusion
//! - Should only be included when this specific collator is authoring
//! - Need priority inclusion over normal pool transactions
//!
//! # Example
//!
//! ```ignore
//! // Create the queue (shared between RPC and proposer)
//! let held_queue = HeldTransactionQueue::<Block>::new();
//!
//! // In RPC handler - queue transaction for next slot
//! held_queue.push(extrinsic);
//!
//! // In proposer - drain and inject before pool transactions
//! for tx in held_queue.drain() {
//!     block_builder.push(tx)?;
//! }
//! ```

pub mod integration;

use parking_lot::Mutex;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

/// A queue for holding transactions until the collator's authoring slot.
///
/// Transactions in this queue:
/// - Are NOT gossiped to other nodes
/// - Are injected BEFORE normal pool transactions during block building
/// - Are cleared after each block is built (whether successful or not)
#[derive(Clone)]
pub struct HeldTransactionQueue<Block: BlockT> {
    pending: Arc<Mutex<Vec<Block::Extrinsic>>>,
}

impl<Block: BlockT> Default for HeldTransactionQueue<Block> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Block: BlockT> HeldTransactionQueue<Block> {
    /// Create a new empty held transaction queue.
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Push a transaction to the held queue.
    ///
    /// The transaction will be held until the next block is authored by this node,
    /// at which point it will be injected into the block before pool transactions.
    pub fn push(&self, xt: Block::Extrinsic) {
        let mut pending = self.pending.lock();
        tracing::debug!(
            target: "held-transactions",
            "Queuing transaction for next authoring slot. Queue size: {}",
            pending.len() + 1
        );
        pending.push(xt);
    }

    /// Push multiple transactions to the held queue.
    pub fn push_batch(&self, xts: impl IntoIterator<Item = Block::Extrinsic>) {
        let mut pending = self.pending.lock();
        let initial_len = pending.len();
        pending.extend(xts);
        tracing::debug!(
            target: "held-transactions",
            "Queued {} transactions for next authoring slot. Queue size: {}",
            pending.len() - initial_len,
            pending.len()
        );
    }

    /// Drain all held transactions.
    ///
    /// This is called by the proposer when building a block. All transactions
    /// are removed from the queue and returned for inclusion in the block.
    pub fn drain(&self) -> Vec<Block::Extrinsic> {
        let mut pending = self.pending.lock();
        let drained = std::mem::take(&mut *pending);
        if !drained.is_empty() {
            tracing::info!(
                target: "held-transactions",
                "Draining {} held transactions for block inclusion",
                drained.len()
            );
        }
        drained
    }

    /// Get the number of held transactions.
    pub fn len(&self) -> usize {
        self.pending.lock().len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.pending.lock().is_empty()
    }

    /// Clear all held transactions without returning them.
    ///
    /// Returns the number of cleared transactions.
    /// Useful for cleanup if block building fails.
    pub fn clear(&self) -> usize {
        let mut pending = self.pending.lock();
        let count = pending.len();
        pending.clear();
        if count > 0 {
            tracing::warn!(
                target: "held-transactions",
                "Cleared {} held transactions",
                count
            );
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_runtime::{
        generic::{Block, Header},
        traits::BlakeTwo256,
        OpaqueExtrinsic,
    };

    type TestBlock = Block<Header<u64, BlakeTwo256>, OpaqueExtrinsic>;

    // Helper to create valid SCALE-encoded OpaqueExtrinsic
    fn make_tx(data: &[u8]) -> OpaqueExtrinsic {
        // OpaqueExtrinsic expects SCALE compact-encoded length prefix
        let mut encoded = vec![(data.len() * 4) as u8]; // compact encoding for small lengths
        encoded.extend_from_slice(data);
        OpaqueExtrinsic::from_bytes(&encoded).unwrap()
    }

    #[test]
    fn push_and_drain_works() {
        let queue = HeldTransactionQueue::<TestBlock>::new();

        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        let tx1 = make_tx(&[1, 2, 3]);
        let tx2 = make_tx(&[4, 5, 6]);

        queue.push(tx1);
        queue.push(tx2);

        assert!(!queue.is_empty());
        assert_eq!(queue.len(), 2);

        let drained = queue.drain();
        assert_eq!(drained.len(), 2);
        assert!(queue.is_empty());

        // Drain again should be empty
        let drained_again = queue.drain();
        assert!(drained_again.is_empty());
    }

    #[test]
    fn push_batch_works() {
        let queue = HeldTransactionQueue::<TestBlock>::new();

        let txs = vec![make_tx(&[1]), make_tx(&[2]), make_tx(&[3])];

        queue.push_batch(txs);
        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn clear_works() {
        let queue = HeldTransactionQueue::<TestBlock>::new();

        queue.push(make_tx(&[1]));
        queue.push(make_tx(&[2]));

        assert_eq!(queue.len(), 2);
        queue.clear();
        assert!(queue.is_empty());
    }

    #[test]
    fn clone_shares_state() {
        let queue1 = HeldTransactionQueue::<TestBlock>::new();
        let queue2 = queue1.clone();

        queue1.push(make_tx(&[1]));
        assert_eq!(queue2.len(), 1);

        let drained = queue2.drain();
        assert_eq!(drained.len(), 1);
        assert!(queue1.is_empty());
    }
}
