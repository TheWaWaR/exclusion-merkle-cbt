
# Exclusion Complete Binary Merkle Tree
A merkle tree based on Nervos [Complete Binary Merkle Tree](https://github.com/nervosnetwork/merkle-tree) to support verifiing a leaf is not on a certain tree.

## Example Usage
```rust
type StrKey = &'static str;
type StrLeaf = SimpleLeaf<StrKey>;
type StrRangeLeaf = SimpleRangeLeaf<StrKey, Blake2bHasher>;
// A helper to compute root and build proof
type StrExCBMT = SimpleExclusionCBMT<StrKey, Blake2bHasher, MergeBlake2bH256>;

// Can be seen as a black list
let all_leaves: Vec<StrLeaf> = vec!["b", "e", "g", "x"]
    .into_iter()
    .map(StrLeaf::new_with_key)
    .collect();
let root = StrExCBMT::compute_root(&all_leaves);
// The keys not in the black list
let excluded_keys = vec!["f", "y", "z", "a"];
let proof = StrExCBMT::build_proof(&all_leaves, &excluded_keys).unwrap();
assert_eq!(
    proof
        .range_leaves()
        .iter()
        .map(|l| (*l.key(), *l.next_key()))
        .collect::<Vec<_>>(),
    vec![("e", "g"), ("x", "b")]
);
assert!(proof
    .verify_exclusion(&root, &excluded_keys)
    .is_ok());
```
