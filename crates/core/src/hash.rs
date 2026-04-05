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
        algs.insert(HashAlgId::BLAKE2S, Box::new(Blake2s::default()));
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
    /// BLAKE2S hash algorithm.
    pub const BLAKE2S: Self = Self(4);
    /// POSEIDON2 hash algorithm
    pub const POSEIDON2: Self = Self(5);

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

    /// Generates a blinder whose 16 bytes form 4 valid M31 field elements.
    ///
    /// BLAKE2s interprets its input as little-endian u32 words. When the VM
    /// backend uses M31 arithmetic (modulus 2^31 - 1), each such word must be
    /// strictly less than 2^31 - 1. This method uses rejection sampling to
    /// guarantee that property without introducing statistical bias.
    pub fn random_m31() -> Self {
        const M31: u32 = (1u32 << 31) - 1;
        let mut bytes = [0u8; 16];
        for chunk in bytes.chunks_exact_mut(4) {
            loop {
                let v = rand::random::<u32>();
                if v < M31 {
                    chunk.copy_from_slice(&v.to_le_bytes());
                    break;
                }
            }
        }
        Blinder(bytes)
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
            super::Hash::new(hasher.finalize().as_ref())
        }

        fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> super::Hash {
            let mut hasher = ::sha2::Sha256::default();
            hasher.update(prefix);
            hasher.update(data);
            super::Hash::new(hasher.finalize().as_ref())
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

mod blake2s {
    use ::blake2::Digest;

    /// BLAKE2S hash algorithm.
    #[derive(Default, Clone)]
    pub struct Blake2s {}

    impl super::HashAlgorithm for Blake2s {
        fn id(&self) -> super::HashAlgId {
            super::HashAlgId::BLAKE2S
        }

        fn hash(&self, data: &[u8]) -> super::Hash {
            let mut hasher = ::blake2::Blake2s256::default();
            hasher.update(data);
            super::Hash::new(hasher.finalize().as_ref())
        }

        fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> super::Hash {
            let mut hasher = ::blake2::Blake2s256::default();
            hasher.update(prefix);
            hasher.update(data);
            super::Hash::new(hasher.finalize().as_ref())
        }
    }
}

pub use blake2s::Blake2s;


mod poseidon2 {
    //! Poseidon2 sponge over M31 (p = 2^31 − 1).
    //!
    //! Each byte of the input is treated as a single M31 field element
    //! (value 0–255).  The sponge uses RATE = 8 elements per block and
    //! zero-pads the last (possibly partial) block.  The 32-byte digest is
    //! the little-endian serialisation of the first RATE output words.

    const P: u32 = (1u32 << 31) - 1;
    const N_STATE: usize = 16;
    const RATE: usize = 8;
    const N_HALF_FULL_ROUNDS: usize = 4;
    const N_PARTIAL_ROUNDS: usize = 14;

    const MAT_INTERNAL_DIAG_M_1: [u32; N_STATE] = [
        0x07b80ac4, 0x6bd9cb33, 0x48ee3f9f, 0x4f63dd19,
        0x18c546b3, 0x5af89e8b, 0x4ff23de8, 0x4f78aaf6,
        0x53bdc6d4, 0x5c59823e, 0x2a471c72, 0x4c975e79,
        0x58dc64d4, 0x06e9315d, 0x2cf32286, 0x2fb6755d,
    ];

    const EXTERNAL_ROUND_CONSTS: [[u32; N_STATE]; 2 * N_HALF_FULL_ROUNDS] = [
        [0x768bab52, 0x70e0ab7d, 0x3d266c8a, 0x6da42045, 0x600fef22, 0x41dace6b, 0x64f9bdd4, 0x5d42d4fe, 0x76b1516d, 0x6fc9a717, 0x70ac4fb6, 0x00194ef6, 0x22b644e2, 0x1f7916d5, 0x47581be2, 0x2710a123],
        [0x6284e867, 0x018d3afe, 0x5df99ef3, 0x4c1e467b, 0x566f6abc, 0x2994e427, 0x538a6d42, 0x5d7bf2cf, 0x7fda2dab, 0x0fd854c4, 0x46922fca, 0x3d7763a1, 0x19fd05ca, 0x0a4bbb43, 0x15075851, 0x3d903d76],
        [0x2d290ff7, 0x40809fa0, 0x59dac6ec, 0x127927a2, 0x6bbf0ea0, 0x0294140f, 0x24742976, 0x6e84c081, 0x22484f4a, 0x354cae59, 0x0453ffe1, 0x3f47a3cc, 0x0088204e, 0x6066e109, 0x3b7c4b80, 0x6b55665d],
        [0x3bc4b897, 0x735bf378, 0x508daf42, 0x1884fc2b, 0x7214f24c, 0x7498be0a, 0x1a60e640, 0x3303f928, 0x29b46376, 0x5c96bb68, 0x65d097a5, 0x1d358e9f, 0x4a9a9017, 0x4724cf76, 0x347af70f, 0x1e77e59a],
        [0x57090613, 0x1fa42108, 0x17bbef50, 0x1ff7e11c, 0x047b24ca, 0x4e140275, 0x4fa086f5, 0x079b309c, 0x1159bd47, 0x6d37e4e5, 0x075d8dce, 0x12121ca0, 0x7f6a7c40, 0x68e182ba, 0x5493201b, 0x0444a80e],
        [0x0064f4c6, 0x6467abe6, 0x66975762, 0x2af68f9b, 0x345b33be, 0x1b70d47f, 0x053db717, 0x381189cb, 0x43b915f8, 0x20df3694, 0x0f459d26, 0x77a0e97b, 0x2f73e739, 0x1876c2f9, 0x65a0e29a, 0x4cabefbe],
        [0x5abd1268, 0x4d34a760, 0x12771799, 0x69a0c9ac, 0x39091e55, 0x7f611cd0, 0x3af055da, 0x7ac0bbdf, 0x6e0f3a24, 0x41e3b6f7, 0x49b3756d, 0x568bc538, 0x20c079d8, 0x1701c72c, 0x7670dc6c, 0x5a439035],
        [0x7c93e00e, 0x561fbb4d, 0x1178907b, 0x02737406, 0x32fb24f1, 0x6323b60a, 0x6ab12418, 0x42c99cea, 0x155a0b97, 0x53d1c6aa, 0x2bd20347, 0x279b3d73, 0x4f5f3c70, 0x0245af6c, 0x238359d3, 0x49966a59],
    ];

    const INTERNAL_ROUND_CONSTS: [u32; N_PARTIAL_ROUNDS] = [
        0x7f7ec4bf, 0x0421926f, 0x5198e669, 0x34db3148, 0x4368bafd, 0x66685c7f,
        0x78d3249a, 0x60187881, 0x76dad67a, 0x0690b437, 0x1ea95311, 0x40e5369a,
        0x38f103fc, 0x1d226a21,
    ];

    #[inline]
    fn add(a: u32, b: u32) -> u32 {
        let s = a.wrapping_add(b);
        if s >= P { s - P } else { s }
    }

    #[inline]
    fn mul(a: u32, b: u32) -> u32 {
        ((a as u64 * b as u64) % P as u64) as u32
    }

    #[inline]
    fn pow5(x: u32) -> u32 {
        let x2 = mul(x, x);
        let x4 = mul(x2, x2);
        mul(x4, x)
    }

    fn apply_m4(x: [u32; 4]) -> [u32; 4] {
        let t0 = add(x[0], x[1]);
        let t1 = add(x[2], x[3]);
        let t02 = add(t0, t0);
        let t12 = add(t1, t1);
        let x1d = add(x[1], x[1]);
        let t2 = add(x1d, t1);
        let x3d = add(x[3], x[3]);
        let t3 = add(x3d, t0);
        let t4 = add(add(t12, t12), t3);
        let t5 = add(add(t02, t02), t2);
        [add(t3, t5), t5, add(t2, t4), t4]
    }

    fn external_matrix(mut s: [u32; N_STATE]) -> [u32; N_STATE] {
        for i in 0..4 {
            let c = apply_m4([s[4*i], s[4*i+1], s[4*i+2], s[4*i+3]]);
            s[4*i..4*i+4].copy_from_slice(&c);
        }
        for j in 0..4 {
            let t = add(add(s[j], s[j+4]), add(s[j+8], s[j+12]));
            s[j]    = add(s[j],    t);
            s[j+4]  = add(s[j+4],  t);
            s[j+8]  = add(s[j+8],  t);
            s[j+12] = add(s[j+12], t);
        }
        s
    }

    fn internal_matrix(mut s: [u32; N_STATE]) -> [u32; N_STATE] {
        let sum = s.iter().fold(0u32, |acc, &x| add(acc, x));
        for i in 0..N_STATE {
            s[i] = add(mul(s[i], MAT_INTERNAL_DIAG_M_1[i]), sum);
        }
        s
    }

    fn permute(mut s: [u32; N_STATE]) -> [u32; N_STATE] {
        s = external_matrix(s);
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..N_STATE { s[i] = add(s[i], EXTERNAL_ROUND_CONSTS[round][i]); }
            for i in 0..N_STATE { s[i] = pow5(s[i]); }
            s = external_matrix(s);
        }
        for round in 0..N_PARTIAL_ROUNDS {
            s[0] = pow5(add(s[0], INTERNAL_ROUND_CONSTS[round]));
            s = internal_matrix(s);
        }
        for round in N_HALF_FULL_ROUNDS..2 * N_HALF_FULL_ROUNDS {
            for i in 0..N_STATE { s[i] = add(s[i], EXTERNAL_ROUND_CONSTS[round][i]); }
            for i in 0..N_STATE { s[i] = pow5(s[i]); }
            s = external_matrix(s);
        }
        s
    }

    fn absorb(mut s: [u32; N_STATE], block: [u32; RATE]) -> [u32; N_STATE] {
        for i in 0..RATE { s[i] = add(s[i], block[i]); }
        permute(s)
    }

    /// Hashes a byte slice with Poseidon2 over M31.
    fn hash_bytes(data: &[u8]) -> [u8; 32] {
        let mut state = [0u32; N_STATE];
        let mut buf = [0u32; RATE];
        let mut pos = 0usize;
        let mut any_block = false;

        for &b in data {
            buf[pos] = b as u32;
            pos += 1;
            if pos == RATE {
                state = absorb(state, buf);
                buf = [0u32; RATE];
                pos = 0;
                any_block = true;
            }
        }
        if !any_block || pos > 0 {
            state = absorb(state, buf);
        }

        let mut out = [0u8; 32];
        for (i, &w) in state[..RATE].iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// Poseidon2 hash algorithm (native, non-VM).
    #[derive(Default, Clone)]
    pub struct Poseidon2 {}

    impl super::HashAlgorithm for Poseidon2 {
        fn id(&self) -> super::HashAlgId {
            super::HashAlgId::POSEIDON2
        }

        fn hash(&self, data: &[u8]) -> super::Hash {
            super::Hash::new(&hash_bytes(data))
        }

        fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> super::Hash {
            let mut combined = Vec::with_capacity(prefix.len() + data.len());
            combined.extend_from_slice(prefix);
            combined.extend_from_slice(data);
            super::Hash::new(&hash_bytes(&combined))
        }
    }
}

pub use poseidon2::Poseidon2;
