
# Exclusion Complete Binary Merkle Tree
A merkle tree based on Nervos [Complete Binary Merkle Tree](https://github.com/nervosnetwork/merkle-tree) to support verifiing a leaf is not on a certain tree.

## Example Usage
```rust
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

let excluded_keys: Vec<StrKey> = vec!["f", "y", "z", "a"];
assert!(proof
    .verify_exclusion(&root, &range_leaves, &excluded_keys)
    .is_ok());
```
