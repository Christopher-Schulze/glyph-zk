// Copyright 2025 Irreducible Inc.

use std::{any::TypeId, collections::BTreeMap, sync::{Arc, OnceLock, RwLock}};

use binius_field::{BinaryField128b, TowerField};
use binius_macros::{DeserializeBytes, SerializeBytes, erased_serialize_bytes};
use binius_utils::DeserializeBytes;

use crate::polynomial::{Error, MultivariatePoly};

type ChallengeMap = BTreeMap<TypeId, Arc<dyn std::any::Any + Send + Sync>>;

fn challenge_store() -> &'static RwLock<ChallengeMap> {
	static STORE: OnceLock<RwLock<ChallengeMap>> = OnceLock::new();
	STORE.get_or_init(|| RwLock::new(BTreeMap::new()))
}

pub fn set_challenge_values<F: TowerField + 'static>(values: Vec<F>) {
	let mut guard = challenge_store()
		.write()
		.expect("challenge store write lock");
	guard.insert(TypeId::of::<F>(), Arc::new(values));
}

fn get_challenge_value<F: TowerField + Copy + 'static>(id: usize) -> Result<F, Error> {
	let guard = challenge_store()
		.read()
		.expect("challenge store read lock");
	let values_any = guard
		.get(&TypeId::of::<F>())
		.ok_or(Error::ChallengeValuesMissing)?;
	let values = values_any
		.downcast_ref::<Vec<F>>()
		.ok_or(Error::ChallengeValuesMissing)?;
	values
		.get(id)
		.copied()
		.ok_or(Error::ChallengeIndexOutOfRange {
			index: id,
			len: values.len(),
		})
}

pub fn challenge_value<F: TowerField + Copy + 'static>(id: usize) -> Result<F, Error> {
	get_challenge_value::<F>(id)
}

/// A challenge-backed constant polynomial. The value is read from a shared challenge store.
#[derive(Debug, Copy, Clone, SerializeBytes, DeserializeBytes)]
pub struct Challenge<F: TowerField> {
	n_vars: usize,
	challenge_id: u32,
	tower_level: usize,
	_marker: std::marker::PhantomData<F>,
}

inventory::submit! {
	<dyn MultivariatePoly<BinaryField128b>>::register_deserializer(
		"Challenge",
		|buf, mode| Ok(Box::new(Challenge::<BinaryField128b>::deserialize(&mut *buf, mode)?))
	)
}

impl<F: TowerField> Challenge<F> {
	pub fn new(challenge_id: u32, tower_level: usize) -> Self {
		Self {
			n_vars: 0,
			challenge_id,
			tower_level,
			_marker: std::marker::PhantomData,
		}
	}
}

#[erased_serialize_bytes]
impl<F: TowerField + Copy + 'static> MultivariatePoly<F> for Challenge<F> {
	fn n_vars(&self) -> usize {
		self.n_vars
	}

	fn degree(&self) -> usize {
		0
	}

	fn evaluate(&self, query: &[F]) -> Result<F, Error> {
		if !query.is_empty() {
			return Err(Error::IncorrectQuerySize {
				expected: 0,
				actual: query.len(),
			});
		}
		get_challenge_value::<F>(self.challenge_id as usize)
	}

	fn binary_tower_level(&self) -> usize {
		self.tower_level
	}
}
