//! Hash types.

use std::{collections::HashMap, fmt::Display};

use rand::{distr::StandardUniform, prelude::Distribution};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Maximum length of a hash value.
const MAX_LEN: usize = 64;

/// An error for [`HashProvider`].
#[derive(Debug, thiserror::Error)]
#[error("unknown hash algorithm id: {}", self.0)]
pub struct HashProviderError(HashAlgId);

/// Hash provider.
pub struct HashProvider {
    algs: HashMap<HashAlgId, Box<dyn HashAlgorithm + Send + Sync>>,
}

impl Default for HashProvider {
    fn default() -> Self {
        let mut algs: HashMap<_, Box<dyn HashAlgorithm + Send + Sync>> = HashMap::new();

        algs.insert(HashAlgId::SHA256, Box::new(Sha256::default()));
        algs.insert(HashAlgId::BLAKE3, Box::new(Blake3::default()));
        algs.insert(HashAlgId::KECCAK256, Box::new(Keccak256::default()));
        algs.insert(HashAlgId::POSEIDON2, Box::new(Poseidon2::default()));

        Self { algs }
    }
}

impl HashProvider {
    /// Sets a hash algorithm.
    ///
    /// This can be used to add or override implementations of hash algorithms.
    pub fn set_algorithm(
        &mut self,
        id: HashAlgId,
        algorithm: Box<dyn HashAlgorithm + Send + Sync>,
    ) {
        self.algs.insert(id, algorithm);
    }

    /// Returns the hash algorithm with the given identifier, or an error if the
    /// hash algorithm does not exist.
    pub fn get(
        &self,
        id: &HashAlgId,
    ) -> Result<&(dyn HashAlgorithm + Send + Sync), HashProviderError> {
        self.algs
            .get(id)
            .map(|alg| &**alg)
            .ok_or(HashProviderError(*id))
    }
}

/// A hash algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashAlgId(u8);

impl HashAlgId {
    /// SHA-256 hash algorithm.
    pub const SHA256: Self = Self(1);
    /// BLAKE3 hash algorithm.
    pub const BLAKE3: Self = Self(2);
    /// Keccak-256 hash algorithm.
    pub const KECCAK256: Self = Self(3);
    /// Poseidon2 hash algorithm over M31 field.
    pub const POSEIDON2: Self = Self(4);

    /// Creates a new hash algorithm identifier.
    ///
    /// # Panics
    ///
    /// Panics if the identifier is in the reserved range 0-127.
    ///
    /// # Arguments
    ///
    /// * id - Unique identifier for the hash algorithm.
    pub const fn new(id: u8) -> Self {
        assert!(id >= 128, "hash algorithm id range 0-127 is reserved");

        Self(id)
    }

    /// Returns the id as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        self.0
    }
}

impl Display for HashAlgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}", self.0)
    }
}

/// A typed hash value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypedHash {
    /// The algorithm of the hash.
    pub alg: HashAlgId,
    /// The hash value.
    pub value: Hash,
}

/// A hash value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash {
    // To avoid heap allocation, we use a fixed-size array.
    // 64 bytes should be sufficient for most hash algorithms.
    value: [u8; MAX_LEN],
    len: usize,
}

impl Default for Hash {
    fn default() -> Self {
        Self {
            value: [0u8; MAX_LEN],
            len: 0,
        }
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(&self.value[..self.len])
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use core::marker::PhantomData;
        use serde::de::{Error, SeqAccess, Visitor};

        struct HashVisitor<'de>(PhantomData<&'de ()>);

        impl<'de> Visitor<'de> for HashVisitor<'de> {
            type Value = Hash;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an array at most 64 bytes long")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut value = [0; MAX_LEN];
                let mut len = 0;

                while let Some(byte) = seq.next_element()? {
                    if len >= MAX_LEN {
                        return Err(A::Error::invalid_length(len, &self));
                    }

                    value[len] = byte;
                    len += 1;
                }

                Ok(Hash { value, len })
            }
        }

        deserializer.deserialize_seq(HashVisitor(PhantomData))
    }
}

impl Hash {
    /// Creates a new hash value.
    ///
    /// # Panics
    ///
    /// Panics if the length of the value is greater than 64 bytes.
    fn new(value: &[u8]) -> Self {
        assert!(
            value.len() <= MAX_LEN,
            "hash value must be at most 64 bytes"
        );

        let mut bytes = [0; MAX_LEN];
        bytes[..value.len()].copy_from_slice(value);

        Self {
            value: bytes,
            len: value.len(),
        }
    }

    /// Returns a byte slice of the hash value.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value[..self.len]
    }
}

impl rs_merkle::Hash for Hash {
    const SIZE: usize = MAX_LEN;
}

impl TryFrom<Vec<u8>> for Hash {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() > MAX_LEN {
            return Err("hash value must be at most 64 bytes");
        }

        let mut bytes = [0; MAX_LEN];
        bytes[..value.len()].copy_from_slice(&value);

        Ok(Self {
            value: bytes,
            len: value.len(),
        })
    }
}

impl From<Hash> for Vec<u8> {
    fn from(value: Hash) -> Self {
        value.value[..value.len].to_vec()
    }
}

/// A hashing algorithm.
pub trait HashAlgorithm {
    /// Returns the hash algorithm identifier.
    fn id(&self) -> HashAlgId;

    /// Computes the hash of the provided data.
    fn hash(&self, data: &[u8]) -> Hash;

    /// Computes the hash of the provided data with a prefix.
    fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> Hash;
}

/// A hash blinder.
#[derive(Clone, Serialize, Deserialize)]
pub struct Blinder([u8; 16]);

opaque_debug::implement!(Blinder);

impl Blinder {
    /// Returns the blinder as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Distribution<Blinder> for StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Blinder {
        let mut blinder = [0; 16];
        rng.fill(&mut blinder);
        Blinder(blinder)
    }
}

/// A blinded pre-image of a hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blinded<T> {
    data: T,
    blinder: Blinder,
}

impl<T> Blinded<T> {
    /// Creates a new blinded pre-image.
    pub fn new(data: T) -> Self {
        Self {
            data,
            blinder: rand::random(),
        }
    }

    /// Returns the data.
    pub fn data(&self) -> &T {
        &self.data
    }
}

mod sha2 {
    use ::sha2::Digest;

    /// SHA-256 hash algorithm.
    #[derive(Default, Clone)]
    pub struct Sha256 {}

    impl super::HashAlgorithm for Sha256 {
        fn id(&self) -> super::HashAlgId {
            super::HashAlgId::SHA256
        }

        fn hash(&self, data: &[u8]) -> super::Hash {
            let mut hasher = ::sha2::Sha256::default();
            hasher.update(data);
            super::Hash::new(hasher.finalize().as_slice())
        }

        fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> super::Hash {
            let mut hasher = ::sha2::Sha256::default();
            hasher.update(prefix);
            hasher.update(data);
            super::Hash::new(hasher.finalize().as_slice())
        }
    }
}

pub use sha2::Sha256;

mod blake3 {

    /// BLAKE3 hash algorithm.
    #[derive(Default, Clone)]
    pub struct Blake3 {}

    impl super::HashAlgorithm for Blake3 {
        fn id(&self) -> super::HashAlgId {
            super::HashAlgId::BLAKE3
        }

        fn hash(&self, data: &[u8]) -> super::Hash {
            super::Hash::new(::blake3::hash(data).as_bytes())
        }

        fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> super::Hash {
            let mut hasher = ::blake3::Hasher::new();
            hasher.update(prefix);
            hasher.update(data);
            super::Hash::new(hasher.finalize().as_bytes())
        }
    }
}

pub use blake3::Blake3;

mod keccak {
    use tiny_keccak::Hasher;

    /// Keccak-256 hash algorithm.
    #[derive(Default, Clone)]
    pub struct Keccak256 {}

    impl super::HashAlgorithm for Keccak256 {
        fn id(&self) -> super::HashAlgId {
            super::HashAlgId::KECCAK256
        }

        fn hash(&self, data: &[u8]) -> super::Hash {
            let mut hasher = tiny_keccak::Keccak::v256();
            hasher.update(data);
            let mut output = vec![0; 32];
            hasher.finalize(&mut output);
            super::Hash::new(&output)
        }

        fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> super::Hash {
            let mut hasher = tiny_keccak::Keccak::v256();
            hasher.update(prefix);
            hasher.update(data);
            let mut output = vec![0; 32];
            hasher.finalize(&mut output);
            super::Hash::new(&output)
        }
    }
}

pub use keccak::Keccak256;

mod poseidon2 {
    use poseidon2_m31::{Poseidon2Sponge, stwo::core::fields::m31::BaseField};

    /// Poseidon2 hash algorithm over M31 field.
    #[derive(Default, Clone)]
    pub struct Poseidon2 {}

    impl super::HashAlgorithm for Poseidon2 {
        fn id(&self) -> super::HashAlgId {
            super::HashAlgId::POSEIDON2
        }

        fn hash(&self, data: &[u8]) -> super::Hash {
            let mut sponge = Poseidon2Sponge::new();

            // Convert bytes to BaseField elements
            for &byte in data {
                sponge.absorb(BaseField::from_u32_unchecked(byte as u32));
            }

            // Get 8 field elements (32 bytes total)
            let result = sponge.finalize_full_rate();

            // Convert field elements to bytes
            let mut output = Vec::with_capacity(32);
            for elem in result.iter() {
                // BaseField is M31, stored as u32
                let value = elem.0;
                output.extend_from_slice(&value.to_le_bytes());
            }

            super::Hash::new(&output)
        }

        fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> super::Hash {
            let mut sponge = Poseidon2Sponge::new();

            // Absorb prefix
            for &byte in prefix {
                sponge.absorb(BaseField::from_u32_unchecked(byte as u32));
            }

            // Absorb data
            for &byte in data {
                sponge.absorb(BaseField::from_u32_unchecked(byte as u32));
            }

            // Get 8 field elements (32 bytes total)
            let result = sponge.finalize_full_rate();

            // Convert field elements to bytes
            let mut output = Vec::with_capacity(32);
            for elem in result.iter() {
                let value = elem.0;
                output.extend_from_slice(&value.to_le_bytes());
            }

            super::Hash::new(&output)
        }
    }
}

pub use poseidon2::Poseidon2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon2_basic_hash() {
        let poseidon = Poseidon2::default();
        let data = b"Hello, Poseidon2!";

        let hash = poseidon.hash(data);

        // Verify hash is deterministic
        let hash2 = poseidon.hash(data);
        assert_eq!(hash.as_bytes(), hash2.as_bytes(), "Hash should be deterministic");

        // Verify different data produces different hash
        let hash3 = poseidon.hash(b"Different data");
        assert_ne!(hash.as_bytes(), hash3.as_bytes(), "Different inputs should produce different hashes");
    }

    #[test]
    fn test_poseidon2_prefixed_hash() {
        let poseidon = Poseidon2::default();
        let prefix = b"prefix:";
        let data = b"data";

        let hash = poseidon.hash_prefixed(prefix, data);

        // Verify it's different from non-prefixed
        let hash_no_prefix = poseidon.hash(data);
        assert_ne!(hash.as_bytes(), hash_no_prefix.as_bytes(), "Prefixed hash should differ from non-prefixed");

        // Verify deterministic
        let hash2 = poseidon.hash_prefixed(prefix, data);
        assert_eq!(hash.as_bytes(), hash2.as_bytes(), "Prefixed hash should be deterministic");
    }

    #[test]
    fn test_poseidon2_algorithm_id() {
        let poseidon = Poseidon2::default();
        assert_eq!(poseidon.id(), HashAlgId::POSEIDON2);
        assert_eq!(HashAlgId::POSEIDON2.as_u8(), 4);
    }

    #[test]
    fn test_poseidon2_in_hash_provider() {
        let provider = HashProvider::default();

        // Verify Poseidon2 is available in default provider
        let hasher = provider.get(&HashAlgId::POSEIDON2).expect("Poseidon2 should be in default provider");

        let data = b"test data";
        let hash = hasher.hash(data);

        // Verify hash has correct algorithm ID
        let typed_hash = TypedHash {
            alg: hasher.id(),
            value: hash,
        };
        assert_eq!(typed_hash.alg, HashAlgId::POSEIDON2);
    }
}
