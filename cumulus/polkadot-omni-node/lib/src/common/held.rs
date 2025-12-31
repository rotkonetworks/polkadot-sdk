// Copyright (C) Rotko Networks OÜ.
// SPDX-License-Identifier: Apache-2.0

//! Held transaction RPC for collators.
//!
//! Provides `author_submitHeld` which queues transactions for inclusion at the
//! next block authoring slot. Unlike `author_submitExtrinsic`, held transactions
//! are NOT visible via `author_pendingExtrinsics` and are NOT gossiped.
//!
//! # Security Model
//!
//! Transactions submitted via this RPC:
//! 1. Are held in a private queue (not the transaction pool)
//! 2. Are invisible to `author_pendingExtrinsics` queries
//! 3. Are flushed to pool with `TransactionSource::Local` priority just before block building
//! 4. Combined with `--reserved-only --reserved-nodes ""` network isolation, prevents gossip
//!
//! This RPC is marked unsafe and disabled by default. Enable with
//! `--rpc-methods unsafe` flag. Only expose to trusted clients.
//!
//! # Use Case
//!
//! Recovery of funds from compromised accounts with sweeper bots:
//! 1. Build signed tx offline
//! 2. Run collator with network isolation and held queue enabled
//! 3. Submit via author_submitHeld
//! 4. When collator's slot arrives, tx is flushed to pool and included in block
//! 5. Tx included in block before attacker sees it

use codec::Decode;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use log::info;
use sc_held_transactions::HeldTransactionQueue;
use sp_core::Bytes;
use sp_runtime::traits::Block as BlockT;

/// RPC trait for held transaction submission.
///
/// Methods are marked unsafe - requires `--rpc-methods unsafe` to enable.
#[rpc(server, client, namespace = "author")]
pub trait HeldTransactionApi {
	/// Submit a transaction to the held queue for inclusion at next authoring slot.
	///
	/// Unlike `author_submitExtrinsic` which adds to the pool immediately (and can
	/// be seen via `author_pendingExtrinsics`), this holds the transaction privately
	/// until the collator's next block authoring slot.
	///
	/// Returns the number of transactions currently held (including this one).
	///
	/// # Safety
	///
	/// This is an unsafe RPC. Only enable for trusted clients.
	#[method(name = "submitHeld")]
	fn submit_held(&self, extrinsic: Bytes) -> RpcResult<usize>;

	/// Get the number of transactions currently in the held queue.
	#[method(name = "heldCount")]
	fn held_count(&self) -> RpcResult<usize>;

	/// Clear all held transactions.
	///
	/// Returns the number of cleared transactions.
	#[method(name = "clearHeld")]
	fn clear_held(&self) -> RpcResult<usize>;
}

/// RPC handler for held transactions.
pub struct HeldTransactionRpc<Block: BlockT> {
	held_queue: HeldTransactionQueue<Block>,
}

impl<Block: BlockT> HeldTransactionRpc<Block> {
	/// Create new held transaction RPC handler.
	pub fn new(held_queue: HeldTransactionQueue<Block>) -> Self {
		Self { held_queue }
	}
}

impl<Block> HeldTransactionApiServer for HeldTransactionRpc<Block>
where
	Block: BlockT,
{
	fn submit_held(&self, extrinsic: Bytes) -> RpcResult<usize> {
		let xt = Block::Extrinsic::decode(&mut &extrinsic[..]).map_err(|e| {
			jsonrpsee::types::ErrorObject::owned(
				1001,
				format!("failed to decode extrinsic: {}", e),
				None::<()>,
			)
		})?;

		self.held_queue.push(xt);
		let count = self.held_queue.len();

		info!(
			target: "held-transactions",
			"Transaction queued for next authoring slot. Queue size: {}",
			count
		);

		Ok(count)
	}

	fn held_count(&self) -> RpcResult<usize> {
		Ok(self.held_queue.len())
	}

	fn clear_held(&self) -> RpcResult<usize> {
		Ok(self.held_queue.clear())
	}
}
