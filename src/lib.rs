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

pub struct ExclusionMerkleProof<T, M> {
    raw_proof: MerkleProof<(T, T), M>,
}

impl<T, M> ExclusionMerkleProof<T, M>
where
    T: Ord + Default + Clone,
    M: Merge<Item = (T, T)>,
{
    /// The underlying proof
    pub fn raw_proof(&self) -> &MerkleProof<(T, T), M> {
        &self.raw_proof
    }

    /// Verify the `values` are all not in the tree, `None` means the `leaves` is not in the tree
    pub fn verify_exclusion(&self, root: &(T, T), leaves: &[(T, T)], values: &[T]) -> Option<bool> {
        if self.raw_proof.verify(root, leaves) {
            for value in values {
                let mut excluded = false;
                for (start_value, end_value) in leaves {
                    match start_value.cmp(end_value) {
                        // This is nomal range
                        Ordering::Less if value > start_value && value < end_value => {
                            excluded = true;
                            break;
                        }
                        // This is the last special range
                        Ordering::Greater if value < end_value || value > start_value => {
                            excluded = true;
                            break;
                        }
                        // There is only one value in tree
                        Ordering::Equal if value != start_value => {
                            debug_assert!(leaves.len() == 1);
                            excluded = true;
                            break;
                        }
                        _ => {}
                    }
                }
                if !excluded {
                    return Some(false);
                }
            }
            Some(true)
        } else {
            None
        }
    }
}

impl<T, M> From<MerkleProof<(T, T), M>> for ExclusionMerkleProof<T, M> {
    fn from(raw_proof: MerkleProof<(T, T), M>) -> Self {
        Self { raw_proof }
    }
}
impl<T, M> From<ExclusionMerkleProof<T, M>> for MerkleProof<(T, T), M> {
    fn from(proof: ExclusionMerkleProof<T, M>) -> Self {
        proof.raw_proof
    }
}

#[derive(Default)]
pub struct ExclusionCMBT<T, M> {
    data_type: PhantomData<T>,
    merge: PhantomData<M>,
}

impl<T, M> ExclusionCMBT<T, M>
where
    T: Ord + Default + Clone,
    M: Merge<Item = (T, T)>,
{
    /// Map value leaves to range leaves
    pub fn map_leaves(mut included_values: Vec<T>) -> Vec<(T, T)> {
        if included_values.is_empty() {
            return Vec::new();
        }
        included_values.sort();
        let mut real_leaves: Vec<(T, T)> = Vec::with_capacity(included_values.len());
        for window in included_values.windows(2) {
            real_leaves.push((window[0].clone(), window[1].clone()));
        }
        real_leaves.push((
            included_values[included_values.len() - 1].clone(),
            included_values[0].clone(),
        ));
        real_leaves
    }

    pub fn build_merkle_root(included_values: &[T]) -> (T, T) {
        if included_values.is_empty() {
            return Default::default();
        }
        CBMT::<(T, T), M>::build_merkle_root(&Self::map_leaves(included_values.to_vec()))
    }

    pub fn build_merkle_tree(included_values: Vec<T>) -> MerkleTree<(T, T), M> {
        CBMT::<(T, T), M>::build_merkle_tree(&Self::map_leaves(included_values))
    }

    pub fn build_merkle_proof(
        included_values: &[T],
        indices: &[u32],
    ) -> Option<ExclusionMerkleProof<T, M>> {
        Self::build_merkle_tree(included_values.to_vec())
            .build_proof(indices)
            .map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MergeI32 {}

    impl Merge for MergeI32 {
        type Item = (i32, i32);
        fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
            (right.0.wrapping_sub(left.0), right.1.wrapping_sub(left.1))
        }
    }

    type ExCBMTI32 = ExclusionCMBT<i32, MergeI32>;

    #[test]
    fn test_simple() {
        let included_values: Vec<i32> = vec![2, 3, 5, 7, 11, 13];
        let all_leaves = ExCBMTI32::map_leaves(included_values.clone());
        let indices: Vec<u32> = vec![1, 3, 5];
        let leaves: Vec<(i32, i32)> = indices
            .iter()
            .map(|index| all_leaves[*index as usize])
            .collect();
        let root = ExCBMTI32::build_merkle_root(&included_values);
        let proof: ExclusionMerkleProof<i32, _> =
            ExCBMTI32::build_merkle_proof(&included_values, &indices).unwrap();

        assert_eq!(leaves, vec![(3, 5), (7, 11), (13, 2)]);
        let excluded_values: Vec<i32> = vec![
            // 3 < x < 5 or 7 < x < 11
            4, 8, 9, 10, // greater than 13
            14, 15, 16, 66, 999, // less than 2
            1, 0, -1, -999,
        ];
        assert_eq!(
            proof.verify_exclusion(&root, &leaves, &excluded_values),
            Some(true)
        );
        let excluded_values: Vec<i32> = vec![4];
        assert_eq!(
            proof.verify_exclusion(&root, &leaves, &excluded_values),
            Some(true)
        );
        let excluded_values: Vec<i32> = vec![9, -999];
        assert_eq!(
            proof.verify_exclusion(&root, &leaves, &excluded_values),
            Some(true)
        );

        // Use invalid leaves to verify the proof
        let invalid_leaves1: Vec<(i32, i32)> = vec![(2, 5), (7, 11), (13, 2)];
        assert_eq!(
            proof.verify_exclusion(&root, &invalid_leaves1, &excluded_values),
            None
        );
        let invalid_leaves2: Vec<(i32, i32)> = vec![(7, 11), (13, 2)];
        assert_eq!(
            proof.verify_exclusion(&root, &invalid_leaves2, &excluded_values),
            None
        );

        // 3 is in `included_values`
        let excluded_values: Vec<i32> = vec![3];
        assert_eq!(
            proof.verify_exclusion(&root, &leaves, &excluded_values),
            Some(false)
        );

        // 3,5 are in `included_values`
        let excluded_values: Vec<i32> = vec![3, 4, 5];
        assert_eq!(
            proof.verify_exclusion(&root, &leaves, &excluded_values),
            Some(false)
        );

        // 12 is not in `included_values`, but the proof can not verify it
        let excluded_values: Vec<i32> = vec![12];
        assert_eq!(
            proof.verify_exclusion(&root, &leaves, &excluded_values),
            Some(false)
        );
    }
}
