use super::{
	to_meta_key, CommitSet, Error, Hash, IsPruned, LastCanonicalized, MetaDb, NomtOverlay,
	PruningMode, StateDbError,
};
use codec::{Decode, Encode};
use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, SessionParams, WitnessMode};
use parking_lot::{Condvar, Mutex, RwLock};
use sp_database::NomtChanges;
use std::{
	collections::{HashMap, VecDeque},
	sync::{Arc, Weak},
};

const OVERLAY_JOURNAL: &[u8] = b"overlay_journal";
pub(crate) const LAST_CANONICAL: &[u8] = b"last_canonical";
const MAX_BLOCKS_PER_LEVEL: u64 = 32;

fn to_journal_key(block: u64, index: u64) -> Vec<u8> {
	to_meta_key(OVERLAY_JOURNAL, &(block, index))
}

pub struct StateDb<BlockHash: Hash, Key: Hash> {
	pub(super) mode: PruningMode,
	last_canonicalized: Option<(BlockHash, u64)>,
	levels: VecDeque<OverlayLevel<BlockHash>>,
	parents: HashMap<BlockHash, BlockHash>,
	canonicalization_lock: Arc<Mutex<()>>,
	_phantom: core::marker::PhantomData<(BlockHash, Key)>,
}

#[cfg_attr(test, derive(PartialEq, Debug))]
struct OverlayLevel<BlockHash: Hash> {
	blocks: Vec<BlockOverlay<BlockHash>>,
	used_indices: u64, // Bitmask of available journal indices.
}

impl<BlockHash: Hash> OverlayLevel<BlockHash> {
	fn push(&mut self, overlay: BlockOverlay<BlockHash>) {
		self.used_indices |= 1 << overlay.journal_index;
		self.blocks.push(overlay)
	}

	fn available_index(&self) -> u64 {
		self.used_indices.trailing_ones() as u64
	}

	fn remove(&mut self, index: usize) -> BlockOverlay<BlockHash> {
		self.used_indices &= !(1 << self.blocks[index].journal_index);
		self.blocks.remove(index)
	}

	fn new() -> OverlayLevel<BlockHash> {
		OverlayLevel { blocks: Vec::new(), used_indices: 0 }
	}
}

#[cfg_attr(test, derive(PartialEq, Debug))]
struct BlockOverlay<BlockHash: Hash> {
	hash: BlockHash,
	journal_index: u64,
	journal_key: Vec<u8>,
	overlay: Arc<NomtOverlay>,
}

#[derive(Encode, Decode)]
struct JournalRecord<BlockHash: Hash> {
	hash: BlockHash,
	parent_hash: BlockHash,
	changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

impl<BlockHash: Hash, Key: Hash> StateDb<BlockHash, Key> {
	/// Creates a new NOMT state database.
	///
	/// This reconstructs the overlay journal from the metadata database on startup.
	/// The journal tracks uncommitted block overlays that haven't been canonicalized yet,
	/// allowing the state DB to handle forks and provide state access for non-canonical blocks.
	///
	/// # Arguments
	/// * `mode` - The pruning mode (currently only affects metadata, as NOMT handles its own pruning)
	/// * `db` - The metadata database for reading journal entries
	/// * `nomt` - The NOMT instance for reconstructing overlays
	///
	/// # Panics
	/// Panics if journal reconstruction fails due to invalid overlay chain.
	pub(super) fn new<D: MetaDb>(
		mode: PruningMode,
		db: &D,
		nomt: Arc<Nomt<Blake3Hasher>>,
	) -> Result<Self, Error<D::Error>> {
		let last_canonicalized =
			db.get_meta(&to_meta_key(LAST_CANONICAL, &())).map_err(Error::Db)?;
		let last_canonicalized = last_canonicalized
			.map(|buffer| <(BlockHash, u64)>::decode(&mut buffer.as_slice()))
			.transpose()?;

		let mut levels = VecDeque::new();
		let mut parents = HashMap::new();
		if let Some((ref hash, mut block)) = last_canonicalized {
			// read the journal
			log::info!("Reading uncanonicalized journal #{} ({:?})", block, hash);
			let mut total: u64 = 0;
			block += 1;

			let mut overlays_map = HashMap::<BlockHash, Vec<Arc<NomtOverlay>>>::new();

			loop {
				let mut level = OverlayLevel::new();
				for index in 0..MAX_BLOCKS_PER_LEVEL {
					let journal_key = to_journal_key(block, index);
					if let Some(record) = db.get_meta(&journal_key).map_err(Error::Db)? {
						let record: JournalRecord<BlockHash> =
							Decode::decode(&mut record.as_slice())?;

						let mut params =
							SessionParams::default().witness_mode(WitnessMode::disabled());

						if let Some(prev_overlays) = overlays_map.get(&record.parent_hash) {
							params = params
								.overlay(prev_overlays.iter().rev().map(|o| o.as_ref()))
								.unwrap();
						}

						let session = nomt.begin_session(params);

						let mut actual_access: Vec<_> = record
							.changes
							.iter()
							.cloned()
							.map(|(key, maybe_val)| (key, KeyReadWrite::Write(maybe_val)))
							.collect();
						actual_access.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));

						let finished = session.finish(actual_access).unwrap();

						let overlay = Arc::new(finished.into_overlay());

						let block_overlay = BlockOverlay {
							hash: record.hash.clone(),
							journal_index: index,
							journal_key,
							overlay: overlay.clone(),
						};

						let mut overlay_chain =
							overlays_map.remove(&record.parent_hash).unwrap_or(vec![]);
						overlay_chain.push(overlay);
						overlays_map.insert(record.hash.clone(), overlay_chain);

						level.push(block_overlay);
						parents.insert(record.hash, record.parent_hash);
						total += 1;
					}
				}
				if level.blocks.is_empty() {
					break
				}
				levels.push_back(level);
				block += 1;
			}
			log::info!("Finished reading uncanonicalized journal, {} entries", total);
		}

		Ok(Self {
			mode,
			levels,
			parents,
			last_canonicalized,
			canonicalization_lock: Arc::new(Mutex::new(())),
			_phantom: core::marker::PhantomData::default(),
		})
	}

	// NOTE: this code assumes that if there is at least one element within
	// the parents map with the key parent_hash, then it is okay to be
	// inserted at the level, but there are no checks that the parent is exactly
	// within the previous level. Should this be done?
	pub(super) fn insert_block(
		&mut self,
		hash: &BlockHash,
		number: u64,
		parent_hash: &BlockHash,
		overlay: NomtOverlay,
	) -> Result<CommitSet<Key>, StateDbError> {
		let mut commit = CommitSet::default();
		let front_block_number = self.front_block_number();

		if self.levels.is_empty() && self.last_canonicalized.is_none() && number > 0 {
			// When inserting a block with number > 0 into an empty state DB (no overlays,
			// no last_canonicalized), we assume the parent block was already canonicalized.
			// This handles the case of starting from a snapshot or genesis sync where we
			// don't have the full history. The parent becomes the implicit last canonical block.
			//
			// Security note: This assumption trusts that the caller provides a valid parent_hash.
			// In production, this should only happen during initial sync or snapshot restoration.
			let last_canonicalized = (parent_hash.clone(), number - 1);
			commit
				.meta
				.inserted
				.push((to_meta_key(LAST_CANONICAL, &()), last_canonicalized.encode()));
			self.last_canonicalized = Some(last_canonicalized);
		} else if self.last_canonicalized.is_some() {
			if number < front_block_number || number > front_block_number + self.levels.len() as u64
			{
				return Err(StateDbError::InvalidBlockNumber)
			}

			if number == front_block_number {
				if !self
					.last_canonicalized
					.as_ref()
					.map_or(false, |&(ref h, n)| h == parent_hash && n == number - 1)
				{
					return Err(StateDbError::InvalidParent)
				}
			} else if !self.parents.contains_key(parent_hash) {
				return Err(StateDbError::InvalidParent)
			}
		}

		let level = if self.levels.is_empty() ||
			number == front_block_number + self.levels.len() as u64
		{
			self.levels.push_back(OverlayLevel::new());
			self.levels.back_mut().expect("can't be empty after insertion; qed")
		} else {
			self.levels.get_mut((number - front_block_number) as usize)
				.expect("number is [front_block_number .. front_block_number + levels.len()) is asserted in precondition; qed")
		};

		self.parents.insert(hash.clone(), parent_hash.clone());

		let index = level.available_index();
		let journal_key = to_journal_key(number, index);

		let journal_record = JournalRecord {
			hash: hash.clone(),
			parent_hash: parent_hash.clone(),
			changes: overlay.changes(),
		};
		commit.meta.inserted.push((journal_key.clone(), journal_record.encode()));

		let overlay = BlockOverlay {
			hash: hash.clone(),
			journal_index: index,
			journal_key,
			overlay: Arc::new(overlay),
		};
		level.push(overlay);

		Ok(commit)
	}

	fn front_block_number(&self) -> u64 {
		self.last_canonicalized.as_ref().map(|&(_, n)| n + 1).unwrap_or(0)
	}

	pub(super) fn canonicalize_block(
		&mut self,
		hash: &BlockHash,
	) -> Result<(NomtChanges, CommitSet<Key>), StateDbError> {
		let mut commit = CommitSet::default();

		let guard = self.canonicalization_lock.lock_arc();

		let Some(level) = self.levels.pop_front() else { return Err(StateDbError::InvalidBlock) };

		// Ensure that the blocks that need to be canonicalized are present within the front level.
		if !level.blocks.iter().any(|block_overlay| &block_overlay.hash == hash) {
			return Err(StateDbError::InvalidBlock)
		}

		let mut discarded_journals = Vec::new();

		// NOTE: this code keeps alive overlays which are built on discarded blocks.
		let mut canonicalized_overlay = None;

		for overlay in level.blocks.into_iter() {
			discarded_journals.push(overlay.journal_key.clone());

			if hash == &overlay.hash {
				canonicalized_overlay = Some(overlay);
			} else {
				self.parents.remove(&overlay.hash);

				// Discard this overlay and all following blocks
				self.discard_journals(0, &mut discarded_journals, &overlay.hash);
			}
		}
		commit.meta.deleted.append(&mut discarded_journals);

		let number = self.front_block_number();
		let canonicalized = (hash.clone(), number);
		commit
			.meta
			.inserted
			.push((to_meta_key(LAST_CANONICAL, &()), canonicalized.encode()));

		self.last_canonicalized = Some(canonicalized);
		// UNWRAP: It has already been confirmed that the overlay is present.
		Ok((
			NomtChanges {
				overlay: canonicalized_overlay.unwrap().overlay,
				_canonicalization_guard: guard,
			},
			commit,
		))
	}

	fn discard_journals(
		&self,
		level_index: usize,
		discarded_journals: &mut Vec<Vec<u8>>,
		hash: &BlockHash,
	) {
		if let Some(level) = self.levels.get(level_index) {
			level.blocks.iter().for_each(|overlay| {
				let parent = self
					.parents
					.get(&overlay.hash)
					.expect("there is a parent entry for each entry in levels; qed")
					.clone();
				if parent == *hash {
					discarded_journals.push(overlay.journal_key.clone());
					self.discard_journals(level_index + 1, discarded_journals, &overlay.hash);
				}
			});
		}
	}

	pub(super) fn last_canonicalized(&self) -> LastCanonicalized {
		self.last_canonicalized
			.as_ref()
			.map(|&(_, n)| LastCanonicalized::Block(n))
			.unwrap_or(LastCanonicalized::None)
	}

	pub(super) fn is_pruned(&self, hash: &BlockHash, number: u64) -> IsPruned {
		let Some((last_canonicalized_hash, last_canonicalized_number)) =
			self.last_canonicalized.as_ref()
		else {
			return IsPruned::NotPruned
		};

		if number < *last_canonicalized_number {
			// Block number is before the last canonicalized block, definitely pruned.
			IsPruned::Pruned
		} else if (&number == last_canonicalized_number && hash == last_canonicalized_hash) ||
			self.parents.contains_key(hash)
		{
			// Either this is the last canonicalized block, or it's tracked in our overlay levels.
			IsPruned::NotPruned
		} else {
			// The block is not in our overlay tracking and is at or after the canonicalized height.
			// This can happen in several scenarios:
			// 1. The block's ancestor was discarded during canonicalization of a competing fork
			// 2. The block was never inserted into our tracking (unknown block)
			// 3. The block is from a fork that was pruned
			//
			// We return MaybePruned to indicate uncertainty - the caller should perform
			// additional checks if they need a definitive answer. This is consistent with
			// the trie-based state DB behavior which also returns MaybePruned for blocks
			// that might have been pruned but aren't definitively known to be.
			IsPruned::MaybePruned
		}
	}

	pub fn wait_for_canonicalization(&self) {
		if self.canonicalization_lock.is_locked() {
			let _guard = self.canonicalization_lock.lock();
		}
	}

	pub fn overlays(&self, hash: &BlockHash) -> Result<Vec<Arc<NomtOverlay>>, StateDbError> {
		let mut overlays = vec![];

		if self.last_canonicalized.as_ref().map_or(false, |(h, _)| h == hash) {
			return Ok(overlays)
		}

		let mut next_hash = hash;
		for level in self.levels.iter().rev() {
			let Some(idx) = level.blocks.iter().position(|overlay| &overlay.hash == next_hash)
			else {
				// The overlay chain cannot be interrupted.
				if !overlays.is_empty() {
					return Err(StateDbError::InvalidBlock)
				}
				continue;
			};

			overlays.push(level.blocks[idx].overlay.clone());

			let Some(parent_hash) = self.parents.get(next_hash) else {
				return Err(StateDbError::InvalidBlock)
			};
			next_hash = parent_hash;
		}

		// The overlay chain can be empty only if the block that we are looking
		// for is the last finalized one, but that has been already checked.
		if overlays.is_empty() {
			return Err(StateDbError::InvalidBlock)
		}

		Ok(overlays)
	}
}
