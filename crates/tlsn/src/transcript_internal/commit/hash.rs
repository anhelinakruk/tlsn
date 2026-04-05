//! Plaintext hash commitments.

use std::collections::HashMap;

use mpz_core::bitvec::BitVec;
use mpz_hash::{blake2s::Blake2s, blake3::Blake3, keccak256::Keccak256, poseidon::Poseidon2, sha256::Sha256};
use mpz_memory_core::{
    DecodeFutureTyped, MemoryExt, Vector,
    binary::{Binary, U8},
};
use mpz_vm_core::{Vm, VmError, prelude::*};
use rangeset::set::RangeSet;
use tlsn_core::{
    hash::{Blinder, Hash, HashAlgId, TypedHash},
    transcript::{
        Direction,
        hash::{PlaintextHash, PlaintextHashSecret},
    },
};

use crate::{Role, transcript_internal::TranscriptRefs};

/// Future which will resolve to the committed hash values.
#[derive(Debug)]

pub(crate) struct HashCommitFuture {
    #[allow(clippy::type_complexity)]
    futs: Vec<(
        Direction,
        RangeSet<usize>,
        HashAlgId,
        DecodeFutureTyped<BitVec, Vec<u8>>,
    )>,
}

impl HashCommitFuture {
    /// Tries to receive the value, returning an error if the value is not
    /// ready.
    pub(crate) fn try_recv(self) -> Result<Vec<PlaintextHash>, HashCommitError> {
        let mut output = Vec::new();
        for (direction, idx, alg, mut fut) in self.futs {
            let hash = fut
                .try_recv()
                .map_err(|_| HashCommitError::decode())?
                .ok_or_else(HashCommitError::decode)?;
            output.push(PlaintextHash {
                direction,
                idx,
                hash: TypedHash {
                    alg,
                    value: Hash::try_from(hash).map_err(HashCommitError::convert)?,
                },
            });
        }

        Ok(output)
    }
}

/// Prove plaintext hash commitments.
pub(crate) fn prove_hash(
    vm: &mut dyn Vm<Binary>,
    refs: &TranscriptRefs,
    idxs: impl IntoIterator<Item = (Direction, RangeSet<usize>, HashAlgId)>,
) -> Result<(HashCommitFuture, Vec<PlaintextHashSecret>), HashCommitError> {
    let mut futs = Vec::new();
    let mut secrets = Vec::new();
    for (direction, idx, alg, hash_ref, blinder_ref) in
        hash_commit_inner(vm, Role::Prover, refs, idxs)?
    {
        let blinder = if alg == HashAlgId::BLAKE2S {
            Blinder::random_m31()
        } else {
            rand::random()
        };

        vm.assign(blinder_ref, blinder.as_bytes().to_vec())?;
        vm.commit(blinder_ref)?;

        let hash_fut = vm.decode(Vector::<U8>::from(hash_ref))?;

        futs.push((direction, idx.clone(), alg, hash_fut));
        secrets.push(PlaintextHashSecret {
            direction,
            idx,
            blinder,
            alg,
        });
    }

    Ok((HashCommitFuture { futs }, secrets))
}

/// Verify plaintext hash commitments.
pub(crate) fn verify_hash(
    vm: &mut dyn Vm<Binary>,
    refs: &TranscriptRefs,
    idxs: impl IntoIterator<Item = (Direction, RangeSet<usize>, HashAlgId)>,
) -> Result<HashCommitFuture, HashCommitError> {
    let mut futs = Vec::new();
    for (direction, idx, alg, hash_ref, blinder_ref) in
        hash_commit_inner(vm, Role::Verifier, refs, idxs)?
    {
        vm.commit(blinder_ref)?;

        let hash_fut = vm.decode(Vector::<U8>::from(hash_ref))?;

        futs.push((direction, idx, alg, hash_fut));
    }

    Ok(HashCommitFuture { futs })
}

#[derive(Clone)]
enum Hasher {
    Sha256(Sha256),
    Blake3(Blake3),
    Keccak256(Keccak256),
    Blake2s(Blake2s),
}

/// Commit plaintext hashes of the transcript.
#[allow(clippy::type_complexity)]
fn hash_commit_inner(
    vm: &mut dyn Vm<Binary>,
    role: Role,
    refs: &TranscriptRefs,
    idxs: impl IntoIterator<Item = (Direction, RangeSet<usize>, HashAlgId)>,
) -> Result<
    Vec<(
        Direction,
        RangeSet<usize>,
        HashAlgId,
        Array<U8, 32>,
        Vector<U8>,
    )>,
    HashCommitError,
> {
    let mut output = Vec::new();
    let mut hashers = HashMap::new();
    for (direction, idx, alg) in idxs {
        let blinder = vm.alloc_vec::<U8>(16)?;
        match role {
            Role::Prover => vm.mark_private(blinder)?,
            Role::Verifier => vm.mark_blind(blinder)?,
        }

        let hash = match alg {
            HashAlgId::SHA256 => {
                let mut hasher = if let Some(Hasher::Sha256(hasher)) = hashers.get(&alg).cloned() {
                    hasher
                } else {
                    let hasher = Sha256::new_with_init(vm).map_err(HashCommitError::hasher)?;
                    hashers.insert(alg, Hasher::Sha256(hasher.clone()));
                    hasher
                };

                let refs = match direction {
                    Direction::Sent => &refs.sent,
                    Direction::Received => &refs.recv,
                };

                for range in idx.iter() {
                    hasher.update(&refs.get(range).expect("plaintext refs are valid"));
                }

                hasher.update(&blinder);
                hasher.finalize(vm).map_err(HashCommitError::hasher)?
            }
            HashAlgId::BLAKE3 => {
                let mut hasher = if let Some(Hasher::Blake3(hasher)) = hashers.get(&alg).cloned() {
                    hasher
                } else {
                    let hasher = Blake3::new(vm).map_err(HashCommitError::hasher)?;
                    hashers.insert(alg, Hasher::Blake3(hasher.clone()));
                    hasher
                };

                let refs = match direction {
                    Direction::Sent => &refs.sent,
                    Direction::Received => &refs.recv,
                };

                for range in idx.iter() {
                    hasher
                        .update(vm, &refs.get(range).expect("plaintext refs are valid"))
                        .map_err(HashCommitError::hasher)?;
                }
                hasher
                    .update(vm, &blinder)
                    .map_err(HashCommitError::hasher)?;
                hasher.finalize(vm).map_err(HashCommitError::hasher)?
            }
            HashAlgId::KECCAK256 => {
                let mut hasher = if let Some(Hasher::Keccak256(hasher)) = hashers.get(&alg).cloned()
                {
                    hasher
                } else {
                    let hasher = Keccak256::new_with_init(vm).map_err(HashCommitError::hasher)?;
                    hashers.insert(alg, Hasher::Keccak256(hasher.clone()));
                    hasher
                };

                let refs = match direction {
                    Direction::Sent => &refs.sent,
                    Direction::Received => &refs.recv,
                };

                for range in idx.iter() {
                    hasher
                        .update(vm, &refs.get(range).expect("plaintext refs are valid"))
                        .map_err(HashCommitError::hasher)?;
                }

                hasher
                    .update(vm, &blinder)
                    .map_err(HashCommitError::hasher)?;
                hasher.finalize(vm).map_err(HashCommitError::hasher)?
            },
            HashAlgId::BLAKE2S => {
                let mut hasher = if let Some(Hasher::Blake2s(hasher)) = hashers.get(&alg).cloned() {
                    hasher
                } else {
                    let hasher = Blake2s::new(vm).map_err(HashCommitError::hasher)?;
                    hashers.insert(alg, Hasher::Blake2s(hasher.clone()));
                    hasher
                };

                let refs = match direction {
                    Direction::Sent => &refs.sent,
                    Direction::Received => &refs.recv,
                };

                for range in idx.iter() {
                    hasher
                        .update(vm, &refs.get(range).expect("plaintext refs are valid"))
                        .map_err(HashCommitError::hasher)?;
                }
                hasher
                    .update(vm, &blinder)
                    .map_err(HashCommitError::hasher)?;
                hasher.finalize(vm).map_err(HashCommitError::hasher)?
            },
            HashAlgId::POSEIDON2 => {
                let refs = match direction {
                    Direction::Sent => &refs.sent,
                    Direction::Received => &refs.recv,
                };

                let mut hasher = Poseidon2::new();
                for range in idx.iter() {
                    hasher
                        .update(vm, &refs.get(range).expect("plaintext refs are valid"))
                        .map_err(HashCommitError::hasher)?;
                }
                hasher.update(vm, &blinder).map_err(HashCommitError::hasher)?;
                hasher.finalize(vm).map_err(HashCommitError::hasher)?
            }
            alg => {
                return Err(HashCommitError::unsupported_alg(alg));
            }
        };

        output.push((direction, idx, alg, hash, blinder));
    }

    Ok(output)
}


/// Error type for hash commitments.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct HashCommitError(#[from] ErrorRepr);

impl HashCommitError {
    fn decode() -> Self {
        Self(ErrorRepr::Decode)
    }

    fn convert(e: &'static str) -> Self {
        Self(ErrorRepr::Convert(e))
    }

    fn hasher<E>(e: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self(ErrorRepr::Hasher(e.into()))
    }

    fn unsupported_alg(alg: HashAlgId) -> Self {
        Self(ErrorRepr::UnsupportedAlg { alg })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("hash commit error: {0}")]
enum ErrorRepr {
    #[error("VM error: {0}")]
    Vm(VmError),
    #[error("failed to decode hash")]
    Decode,
    #[error("failed to convert hash: {0}")]
    Convert(&'static str),
    #[error("unsupported hash algorithm: {alg}")]
    UnsupportedAlg { alg: HashAlgId },
    #[error("hasher error: {0}")]
    Hasher(Box<dyn std::error::Error + Send + Sync>),
}

impl From<VmError> for HashCommitError {
    fn from(value: VmError) -> Self {
        Self(ErrorRepr::Vm(value))
    }
}

#[cfg(test)]
mod tests {
    use mpz_common::context::test_st_context;
    use mpz_ideal_vm::IdealVm;
    use mpz_vm_core::prelude::*;
    use tlsn_core::hash::{HashAlgorithm, Poseidon2 as NativePoseidon2};

    use super::*;

    async fn vm_poseidon2(data: &[u8], blinder: &[u8]) -> [u8; 32] {
        let (mut ctx, _) = test_st_context(1024);
        let mut vm = IdealVm::default();

        let mut hasher = Poseidon2::new();

        if !data.is_empty() {
            let data_ref = vm.alloc_vec::<U8>(data.len()).unwrap();
            vm.mark_public(data_ref).unwrap();
            vm.assign(data_ref, data.to_vec()).unwrap();
            vm.commit(data_ref).unwrap();
            hasher.update(&mut vm, &data_ref).unwrap();
        }

        if !blinder.is_empty() {
            let blinder_ref = vm.alloc_vec::<U8>(blinder.len()).unwrap();
            vm.mark_public(blinder_ref).unwrap();
            vm.assign(blinder_ref, blinder.to_vec()).unwrap();
            vm.commit(blinder_ref).unwrap();
            hasher.update(&mut vm, &blinder_ref).unwrap();
        }

        let hash_ref = hasher.finalize(&mut vm).unwrap();
        let mut fut = vm.decode(Vector::<U8>::from(hash_ref)).unwrap();
        vm.execute_all(&mut ctx).await.unwrap();

        let bytes: Vec<u8> = fut.try_recv().unwrap().unwrap();
        bytes.try_into().unwrap()
    }

    #[rstest::rstest]
    #[case::empty(b"" as &[u8], b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" as &[u8])]
    #[case::short(b"hello", b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10")]
    #[case::one_full_block(b"12345678", b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x77\x88\x99\x00")]
    #[case::multi_block(b"the quick brown fox jumps over", b"\xde\xad\xbe\xef\xca\xfe\xba\xbe\x01\x23\x45\x67\x89\xab\xcd\xef")]
    #[tokio::test]
    async fn test_poseidon2_vm_matches_native(#[case] data: &[u8], #[case] blinder: &[u8]) {
        let vm_hash = vm_poseidon2(data, blinder).await;

        let hasher = NativePoseidon2::default();
        let native_hash = hasher.hash_prefixed(data, blinder);

        assert_eq!(
            vm_hash,
            native_hash.as_bytes(),
            "VM Poseidon2 hash != native for data={data:?} blinder={blinder:?}"
        );
    }
}
