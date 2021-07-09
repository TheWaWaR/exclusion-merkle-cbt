#![cfg_attr(not(feature = "std"), no_std)]

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use std::vec::Vec;
    } else {
        extern crate alloc;
        use alloc::vec::Vec;
    }
}
use core::cmp::Ordering;
use core::marker::PhantomData;
use merkle_cbt::{merkle_tree::Merge, MerkleProof, MerkleTree, CBMT};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error<T> {
    /// The proof is invalid
    InvalidProof,
    /// Key already included in tree
    KeyIncluded(T),
    /// Key not coverted in proof
    KeyUnknown(T),
}

pub type H256 = [u8; 32];

/// Trait for customize hash function
pub trait Hasher {
    fn update(&mut self, data: &[u8]);
    fn finish(self) -> H256;
}

/// The Leaf data
#[derive(Clone)]
pub struct Leaf<K, V> {
    // For sort the leaves before build range leaves
    key: K,
    // If given, the data will be hashed in RangeLeaf.hash()
    value: Option<V>,
}

impl<K, V> Leaf<K, V>
where
    K: Ord + AsRef<[u8]> + Clone,
    V: AsRef<[u8]> + Clone,
{
    pub fn new(key: K, value: Option<V>) -> Self {
        Leaf { key, value }
    }
    pub fn new_with_key(key: K) -> Self {
        Self::new(key, None)
    }
    pub fn key(&self) -> &K {
        &self.key
    }
    pub fn value(&self) -> Option<&V> {
        self.value.as_ref()
    }
    pub fn to_range<H: Hasher + Default>(&self, next_leaf: &Self) -> RangeLeaf<K, V, H> {
        RangeLeaf::new(self.key.clone(), next_leaf.key.clone(), self.value.clone())
    }
    pub fn into_range<H: Hasher + Default>(self, next_leaf: &Self) -> RangeLeaf<K, V, H> {
        RangeLeaf::new(self.key, next_leaf.key.clone(), self.value)
    }
}

pub struct RangeLeaf<K, V, H> {
    key: K,
    next_key: K,
    value: Option<V>,
    hash_type: PhantomData<H>,
}

impl<K, V, H> Clone for RangeLeaf<K, V, H>
where
    K: Ord + AsRef<[u8]> + Clone,
    V: AsRef<[u8]> + Clone,
    H: Hasher + Default,
{
    fn clone(&self) -> Self {
        Self::new(self.key.clone(), self.next_key.clone(), self.value.clone())
    }
}

impl<K, V, H> RangeLeaf<K, V, H>
where
    K: Ord + AsRef<[u8]> + Clone,
    V: AsRef<[u8]> + Clone,
    H: Hasher + Default,
{
    pub fn new(key: K, next_key: K, value: Option<V>) -> Self {
        RangeLeaf {
            key,
            next_key,
            value,
            hash_type: PhantomData,
        }
    }
    pub fn new_with_key_pair(key: K, next_key: K) -> Self {
        Self::new(key, next_key, None)
    }
    pub fn key(&self) -> &K {
        &self.key
    }
    pub fn next_key(&self) -> &K {
        &self.next_key
    }
    pub fn value(&self) -> Option<&V> {
        self.value.as_ref()
    }
    pub fn match_either_key(&self, key: &K) -> bool {
        &self.key == key || &self.next_key == key
    }
    pub fn match_range(&self, key: &K) -> bool {
        match self.key.cmp(&self.next_key) {
            // This is nomal range
            Ordering::Less if key > &self.key && key < &self.next_key => true,
            // This is the last special range
            Ordering::Greater if key < &self.next_key || key > &self.key => true,
            // There is only one value in tree
            Ordering::Equal if key != &self.key => true,
            _ => false,
        }
    }
    pub fn hash(&self) -> H256 {
        let mut hasher = H::default();
        hasher.update(self.key.as_ref());
        hasher.update(self.next_key.as_ref());
        if let Some(value) = self.value.as_ref() {
            hasher.update(value.as_ref());
        }
        hasher.finish()
    }
}

pub struct ExclusionMerkleProof<M> {
    raw_proof: MerkleProof<H256, M>,
}

impl<M> ExclusionMerkleProof<M>
where
    M: Merge<Item = H256>,
{
    /// The underlying proof
    pub fn raw_proof(&self) -> &MerkleProof<H256, M> {
        &self.raw_proof
    }

    /// Verify the `keys` are all not in tree, `None` means the `leaves` is not in the tree.
    ///
    ///  * Ok(())                      => All keys are not in tree
    ///  * Err(Error::InvalidProof)    => The proof don't match the root
    ///  * Err(Error::KeyIncluded(T))  => Some keys are in tree
    ///  * Err(Error::KeyUnknown(T))   => The proof is ok, but some keys not coverted in the range
    pub fn verify_exclusion<K, V, H>(
        &self,
        root: &H256,
        range_leaves: &[RangeLeaf<K, V, H>],
        keys: &[K],
    ) -> Result<(), Error<K>>
    where
        K: Ord + AsRef<[u8]> + Clone,
        V: AsRef<[u8]> + Clone,
        H: Hasher + Default,
    {
        let leaf_hashes: Vec<H256> = range_leaves.iter().map(RangeLeaf::hash).collect();
        if self.raw_proof.verify(root, &leaf_hashes) {
            for key in keys {
                let mut excluded = false;
                for range_leaf in range_leaves {
                    if range_leaf.match_either_key(key) {
                        return Err(Error::KeyIncluded(key.clone()));
                    }
                    if range_leaf.match_range(key) {
                        excluded = true;
                        break;
                    }
                }
                if !excluded {
                    return Err(Error::KeyUnknown(key.clone()));
                }
            }
            Ok(())
        } else {
            Err(Error::InvalidProof)
        }
    }
}

impl<M> From<MerkleProof<H256, M>> for ExclusionMerkleProof<M> {
    fn from(raw_proof: MerkleProof<H256, M>) -> Self {
        Self { raw_proof }
    }
}
impl<M> From<ExclusionMerkleProof<M>> for MerkleProof<H256, M> {
    fn from(proof: ExclusionMerkleProof<M>) -> Self {
        proof.raw_proof
    }
}

#[derive(Default)]
pub struct ExclusionCBMT<K, V, H, M> {
    key_type: PhantomData<K>,
    value_type: PhantomData<V>,
    hash_type: PhantomData<H>,
    merge: PhantomData<M>,
}

impl<K, V, H, M> ExclusionCBMT<K, V, H, M>
where
    K: Ord + AsRef<[u8]> + Clone,
    V: AsRef<[u8]> + Clone,
    H: Hasher + Default,
    M: Merge<Item = H256>,
{
    /// Build range leaves by raw leaves
    pub fn build_range_leaves(mut raw_leaves: Vec<Leaf<K, V>>) -> Vec<RangeLeaf<K, V, H>> {
        if raw_leaves.is_empty() {
            return Vec::new();
        }
        raw_leaves.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        let mut range_leaves: Vec<_> = Vec::with_capacity(raw_leaves.len());
        for window in raw_leaves.windows(2) {
            range_leaves.push(window[0].to_range(&window[1]));
        }
        range_leaves.push(raw_leaves[raw_leaves.len() - 1].to_range(&raw_leaves[0]));
        range_leaves
    }

    pub fn build_merkle_root(raw_leaves: &[Leaf<K, V>]) -> H256 {
        if raw_leaves.is_empty() {
            return Default::default();
        }
        let range_leaves = Self::build_range_leaves(raw_leaves.to_vec());
        let range_leaf_hashes: Vec<_> = range_leaves.iter().map(RangeLeaf::hash).collect();
        CBMT::<H256, M>::build_merkle_root(&range_leaf_hashes)
    }

    pub fn build_merkle_tree(raw_leaves: Vec<Leaf<K, V>>) -> MerkleTree<H256, M> {
        let range_leaves = Self::build_range_leaves(raw_leaves.to_vec());
        let range_leaf_hashes: Vec<_> = range_leaves.iter().map(RangeLeaf::hash).collect();
        CBMT::<H256, M>::build_merkle_tree(&range_leaf_hashes)
    }

    pub fn build_merkle_proof(
        raw_leaves: &[Leaf<K, V>],
        indices: &[u32],
    ) -> Option<ExclusionMerkleProof<M>> {
        Self::build_merkle_tree(raw_leaves.to_vec())
            .build_proof(indices)
            .map(Into::into)
    }
}

pub type SimpleValue = [u8; 0];
pub type SimpleLeaf<K> = Leaf<K, SimpleValue>;
pub type SimpleRangeLeaf<K, H> = RangeLeaf<K, SimpleValue, H>;
pub type SimpleExclusionCBMT<K, H, M> = ExclusionCBMT<K, SimpleValue, H, M>;

#[cfg(test)]
mod tests {
    use super::*;
    use blake2b_rs::{Blake2b, Blake2bBuilder};

    pub struct Blake2bHasher(Blake2b);

    const PERSONALIZATION: &[u8] = b"exclusioncbmtree";
    impl Default for Blake2bHasher {
        fn default() -> Self {
            let blake2b = Blake2bBuilder::new(32).personal(PERSONALIZATION).build();
            Blake2bHasher(blake2b)
        }
    }

    impl Hasher for Blake2bHasher {
        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }
        fn finish(self) -> H256 {
            let mut hash = [0u8; 32];
            self.0.finalize(&mut hash);
            hash
        }
    }

    struct MergeBlake2bH256 {}

    impl Merge for MergeBlake2bH256 {
        type Item = H256;
        fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
            let mut hasher = Blake2bHasher::default();
            hasher.update(left);
            hasher.update(right);
            hasher.finish()
        }
    }

    type StrKey = &'static str;
    type StrLeaf = SimpleLeaf<StrKey>;
    type StrRangeLeaf = SimpleRangeLeaf<StrKey, Blake2bHasher>;
    type StrExCBMT = SimpleExclusionCBMT<StrKey, Blake2bHasher, MergeBlake2bH256>;

    #[test]
    fn test_simple() {
        let all_leaves: Vec<StrLeaf> = vec!["b", "e", "g", "x"]
            .into_iter()
            .map(StrLeaf::new_with_key)
            .collect();
        let all_range_leaves = StrExCBMT::build_range_leaves(all_leaves.clone());
        // ["e", "x"] => [("e", "g"), ("x", "b")]
        let indices: Vec<u32> = vec![1, 3];
        let range_leaves: Vec<StrRangeLeaf> = indices
            .iter()
            .map(|index| all_range_leaves[*index as usize].clone())
            .collect();
        let root = StrExCBMT::build_merkle_root(&all_leaves);
        let proof: ExclusionMerkleProof<MergeBlake2bH256> =
            StrExCBMT::build_merkle_proof(&all_leaves, &indices).unwrap();

        assert_eq!(
            range_leaves
                .iter()
                .map(|l| (*l.key(), *l.next_key()))
                .collect::<Vec<_>>(),
            vec![("e", "g"), ("x", "b")]
        );
        let excluded_keys: Vec<StrKey> = vec!["f", "y", "z", "a"];
        assert!(proof
            .verify_exclusion(&root, &range_leaves, &excluded_keys)
            .is_ok());
        let excluded_keys: Vec<StrKey> = vec!["f"];
        assert!(proof
            .verify_exclusion(&root, &range_leaves, &excluded_keys)
            .is_ok());
        let excluded_keys: Vec<StrKey> = vec!["f", "y", "z", "a"];
        assert!(proof
            .verify_exclusion(&root, &range_leaves, &excluded_keys)
            .is_ok());

        // Use invalid leaves to verify the proof
        let invalid_leaves1: Vec<StrRangeLeaf> = vec![("b", "e"), ("e", "g"), ("x", "b")]
            .into_iter()
            .map(|(key, next_key)| StrRangeLeaf::new_with_key_pair(key, next_key))
            .collect();
        assert_eq!(
            proof.verify_exclusion(&root, &invalid_leaves1, &excluded_keys),
            Err(Error::InvalidProof)
        );
        let invalid_leaves2: Vec<StrRangeLeaf> = vec![("d", "g"), ("x", "b")]
            .into_iter()
            .map(|(key, next_key)| StrRangeLeaf::new_with_key_pair(key, next_key))
            .collect();
        assert_eq!(
            proof.verify_exclusion(&root, &invalid_leaves2, &excluded_keys),
            Err(Error::InvalidProof)
        );

        // "e" is in included keys
        let excluded_keys: Vec<StrKey> = vec!["e"];
        assert_eq!(
            proof.verify_exclusion(&root, &range_leaves, &excluded_keys),
            Err(Error::KeyIncluded("e"))
        );

        // "e","x" are in included keys
        let excluded_keys: Vec<StrKey> = vec!["e", "f", "x"];
        assert_eq!(
            proof.verify_exclusion(&root, &range_leaves, &excluded_keys),
            Err(Error::KeyIncluded("e"))
        );

        // "c" is not in included keys, but the proof can not verify it
        let excluded_keys: Vec<StrKey> = vec!["c"];
        assert_eq!(
            proof.verify_exclusion(&root, &range_leaves, &excluded_keys),
            Err(Error::KeyUnknown("c"))
        );
    }
}
