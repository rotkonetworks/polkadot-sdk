// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use codec::{Decode, DecodeWithMemTracking, Encode};
use frame_election_provider_support::{
	bounds::{ElectionBounds, ElectionBoundsBuilder},
	onchain, SequentialPhragmen, Weight,
};
use frame_support::{
	construct_runtime, derive_impl, parameter_types,
	traits::{ConstU32, ConstU64, KeyOwnerProofSystem, OnFinalize, OnInitialize},
};
use frame_system::pallet_prelude::HeaderFor;
use pallet_session::historical as pallet_session_historical;
use scale_info::TypeInfo;
use sp_core::{crypto::KeyTypeId, ConstBool, ConstU128};
use sp_runtime::{
	app_crypto::ecdsa::Public,
	curve::PiecewiseLinear,
	impl_opaque_keys,
	testing::TestXt,
	traits::{Header as HeaderT, OpaqueKeys},
	BuildStorage, Perbill,
};
use sp_staking::{EraIndex, SessionIndex};
use sp_state_machine::BasicExternalities;

use crate as pallet_beefy;

pub use sp_consensus_beefy::{ecdsa_crypto::AuthorityId as BeefyId, ConsensusLog, BEEFY_ENGINE_ID};
use sp_consensus_beefy::{AncestryHelper, AncestryHelperWeightInfo, Commitment};

impl_opaque_keys! {
	pub struct MockSessionKeys {
		pub dummy: pallet_beefy::Pallet<Test>,
	}
}

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
	pub enum Test
	{
		System: frame_system,
		Authorship: pallet_authorship,
		Timestamp: pallet_timestamp,
		Balances: pallet_balances,
		Beefy: pallet_beefy,
		Staking: pallet_staking,
		Session: pallet_session,
		Offences: pallet_offences,
		Historical: pallet_session_historical,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountData = pallet_balances::AccountData<u128>;
}

impl<C> frame_system::offchain::CreateTransactionBase<C> for Test
where
	RuntimeCall: From<C>,
{
	type RuntimeCall = RuntimeCall;
	type Extrinsic = TestXt<RuntimeCall, ()>;
}

impl<C> frame_system::offchain::CreateBare<C> for Test
where
	RuntimeCall: From<C>,
{
	fn create_bare(call: Self::RuntimeCall) -> Self::Extrinsic {
		TestXt::new_bare(call)
	}
}

#[derive(Clone, Debug, Decode, Encode, PartialEq, TypeInfo)]
pub struct MockAncestryProofContext {
	pub is_valid: bool,
}

#[derive(Clone, Debug, Decode, DecodeWithMemTracking, Encode, PartialEq, TypeInfo)]
pub struct MockAncestryProof {
	pub is_optimal: bool,
	pub is_non_canonical: bool,
}

parameter_types! {
	pub const Period: u64 = 1;
	pub const ReportLongevity: u64 =
		BondingDuration::get() as u64 * SessionsPerEra::get() as u64 * Period::get();
	pub const MaxSetIdSessionEntries: u32 = BondingDuration::get() * SessionsPerEra::get();

	pub storage AncestryProofContext: Option<MockAncestryProofContext> = Some(
		MockAncestryProofContext {
			is_valid: true,
		}
	);
}

pub struct MockAncestryHelper;

impl<Header: HeaderT> AncestryHelper<Header> for MockAncestryHelper {
	type Proof = MockAncestryProof;
	type ValidationContext = MockAncestryProofContext;

	fn generate_proof(
		_prev_block_number: Header::Number,
		_best_known_block_number: Option<Header::Number>,
	) -> Option<Self::Proof> {
		unimplemented!()
	}

	fn is_proof_optimal(proof: &Self::Proof) -> bool {
		proof.is_optimal
	}

	fn extract_validation_context(_header: Header) -> Option<Self::ValidationContext> {
		AncestryProofContext::get()
	}

	fn is_non_canonical(
		_commitment: &Commitment<Header::Number>,
		proof: Self::Proof,
		context: Self::ValidationContext,
	) -> bool {
		context.is_valid && proof.is_non_canonical
	}
}

impl<Header: HeaderT> AncestryHelperWeightInfo<Header> for MockAncestryHelper {
	fn is_proof_optimal(_proof: &<Self as AncestryHelper<HeaderFor<Test>>>::Proof) -> Weight {
		unimplemented!()
	}

	fn extract_validation_context() -> Weight {
		unimplemented!()
	}

	fn is_non_canonical(_proof: &<Self as AncestryHelper<HeaderFor<Test>>>::Proof) -> Weight {
		unimplemented!()
	}
}

impl pallet_beefy::Config for Test {
	type BeefyId = BeefyId;
	type MaxAuthorities = ConstU32<100>;
	type MaxNominators = ConstU32<1000>;
	type MaxSetIdSessionEntries = MaxSetIdSessionEntries;
	type OnNewValidatorSet = ();
	type AncestryHelper = MockAncestryHelper;
	type WeightInfo = ();
	type KeyOwnerProof = <Historical as KeyOwnerProofSystem<(KeyTypeId, BeefyId)>>::Proof;
	type EquivocationReportSystem =
		super::EquivocationReportSystem<Self, Offences, Historical, ReportLongevity>;
}

parameter_types! {
	pub const DisabledValidatorsThreshold: Perbill = Perbill::from_percent(33);
}

impl pallet_session::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type ValidatorId = u64;
	type ValidatorIdOf = sp_runtime::traits::ConvertInto;
	type ShouldEndSession = pallet_session::PeriodicSessions<ConstU64<1>, ConstU64<0>>;
	type NextSessionRotation = pallet_session::PeriodicSessions<ConstU64<1>, ConstU64<0>>;
	type SessionManager = pallet_session::historical::NoteHistoricalRoot<Self, Staking>;
	type SessionHandler = <MockSessionKeys as OpaqueKeys>::KeyTypeIdProviders;
	type Keys = MockSessionKeys;
	type DisablingStrategy = ();
	type WeightInfo = ();
	type Currency = Balances;
	type KeyDeposit = ();
}

impl pallet_session::historical::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type FullIdentification = ();
	type FullIdentificationOf = pallet_staking::UnitIdentificationOf<Self>;
}

impl pallet_authorship::Config for Test {
	type FindAuthor = ();
	type EventHandler = ();
}

type Balance = u128;
#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type Balance = Balance;
	type ExistentialDeposit = ConstU128<1>;
	type AccountStore = System;
}

impl pallet_timestamp::Config for Test {
	type Moment = u64;
	type OnTimestampSet = ();
	type MinimumPeriod = ConstU64<3>;
	type WeightInfo = ();
}

pallet_staking_reward_curve::build! {
	const REWARD_CURVE: PiecewiseLinear<'static> = curve!(
		min_inflation: 0_025_000u64,
		max_inflation: 0_100_000,
		ideal_stake: 0_500_000,
		falloff: 0_050_000,
		max_piece_count: 40,
		test_precision: 0_005_000,
	);
}

parameter_types! {
	pub const SessionsPerEra: SessionIndex = 3;
	pub const BondingDuration: EraIndex = 3;
	pub const RewardCurve: &'static PiecewiseLinear<'static> = &REWARD_CURVE;
	pub static ElectionsBoundsOnChain: ElectionBounds = ElectionBoundsBuilder::default().build();
}

pub struct OnChainSeqPhragmen;
impl onchain::Config for OnChainSeqPhragmen {
	type System = Test;
	type Solver = SequentialPhragmen<u64, Perbill>;
	type DataProvider = Staking;
	type WeightInfo = ();
	type MaxWinnersPerPage = ConstU32<100>;
	type MaxBackersPerWinner = ConstU32<100>;
	type Sort = ConstBool<true>;
	type Bounds = ElectionsBoundsOnChain;
}

#[derive_impl(pallet_staking::config_preludes::TestDefaultConfig)]
impl pallet_staking::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type OldCurrency = Balances;
	type Currency = Balances;
	type AdminOrigin = frame_system::EnsureRoot<Self::AccountId>;
	type SessionInterface = Self;
	type UnixTime = pallet_timestamp::Pallet<Test>;
	type EraPayout = pallet_staking::ConvertCurve<RewardCurve>;
	type NextNewSession = Session;
	type ElectionProvider = onchain::OnChainExecution<OnChainSeqPhragmen>;
	type GenesisElectionProvider = Self::ElectionProvider;
	type VoterList = pallet_staking::UseNominatorsAndValidatorsMap<Self>;
	type TargetList = pallet_staking::UseValidatorsMap<Self>;
}

impl pallet_offences::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type IdentificationTuple = pallet_session::historical::IdentificationTuple<Self>;
	type OnOffenceHandler = Staking;
}

#[derive(Default)]
pub struct ExtBuilder {
	authorities: Vec<BeefyId>,
}

impl ExtBuilder {
	/// Add some AccountIds to insert into `List`.
	#[cfg(test)]
	pub(crate) fn add_authorities(mut self, ids: Vec<BeefyId>) -> Self {
		self.authorities = ids;
		self
	}

	pub fn build(self) -> sp_io::TestExternalities {
		sp_tracing::try_init_simple();
		let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();

		let balances: Vec<_> =
			(0..self.authorities.len()).map(|i| (i as u64, 10_000_000)).collect();

		pallet_balances::GenesisConfig::<Test> { balances, ..Default::default() }
			.assimilate_storage(&mut t)
			.unwrap();

		let session_keys: Vec<_> = self
			.authorities
			.iter()
			.enumerate()
			.map(|(i, k)| (i as u64, i as u64, MockSessionKeys { dummy: k.clone() }))
			.collect();

		BasicExternalities::execute_with_storage(&mut t, || {
			for (ref id, ..) in &session_keys {
				frame_system::Pallet::<Test>::inc_providers(id);
			}
		});

		pallet_session::GenesisConfig::<Test> { keys: session_keys, ..Default::default() }
			.assimilate_storage(&mut t)
			.unwrap();

		// controllers are same as stash
		let stakers: Vec<_> = (0..self.authorities.len())
			.map(|i| (i as u64, i as u64, 10_000, pallet_staking::StakerStatus::<u64>::Validator))
			.collect();

		let staking_config = pallet_staking::GenesisConfig::<Test> {
			stakers,
			validator_count: 2,
			force_era: pallet_staking::Forcing::ForceNew,
			minimum_validator_count: 0,
			invulnerables: vec![],
			..Default::default()
		};

		staking_config.assimilate_storage(&mut t).unwrap();

		t.into()
	}

	pub fn build_and_execute(self, test: impl FnOnce() -> ()) {
		self.build().execute_with(|| {
			test();
			Beefy::do_try_state().expect("All invariants must hold after a test");
		})
	}
}

// Note, that we can't use `UintAuthorityId` here. Reason is that the implementation
// of `to_public_key()` assumes, that a public key is 32 bytes long. This is true for
// ed25519 and sr25519 but *not* for ecdsa. A compressed ecdsa public key is 33 bytes,
// with the first one containing information to reconstruct the uncompressed key.
pub fn mock_beefy_id(id: u8) -> BeefyId {
	let mut buf: [u8; 33] = [id; 33];
	// Set to something valid.
	buf[0] = 0x02;
	let pk = Public::from_raw(buf);
	BeefyId::from(pk)
}

pub fn mock_authorities(vec: Vec<u8>) -> Vec<BeefyId> {
	vec.into_iter().map(|id| mock_beefy_id(id)).collect()
}

pub fn start_session(session_index: SessionIndex) {
	for i in Session::current_index()..session_index {
		System::on_finalize(System::block_number());
		Session::on_finalize(System::block_number());
		Staking::on_finalize(System::block_number());
		Beefy::on_finalize(System::block_number());

		let parent_hash = if System::block_number() > 1 {
			let hdr = System::finalize();
			hdr.hash()
		} else {
			System::parent_hash()
		};

		System::reset_events();
		System::initialize(&(i as u64 + 1), &parent_hash, &Default::default());
		System::set_block_number((i + 1).into());
		Timestamp::set_timestamp(System::block_number() * 6000);

		System::on_initialize(System::block_number());
		Session::on_initialize(System::block_number());
		Staking::on_initialize(System::block_number());
		Beefy::on_initialize(System::block_number());
	}

	assert_eq!(Session::current_index(), session_index);
}

pub fn start_era(era_index: EraIndex) {
	start_session((era_index * 3).into());
	assert_eq!(pallet_staking::CurrentEra::<Test>::get(), Some(era_index));
}
