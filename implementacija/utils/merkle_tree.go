package utils

import (
	"fmt"
	"math/big"

	"multisig/config"
)

type Node struct {
	Hash *big.Int
}

type MerkleTree struct {
	Root   *Node
	Levels [][]*Node
}

// NewMerkleTree constructs a Merkle tree from the given data.
func NewMerkleTree(params *config.Params, data []*big.Int) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("no data provided")
	}

	// 1. Build the leaves (lowest level)
	leaves := make([]*Node, len(data))
	for i, d := range data {
		leaves[i] = &Node{Hash: HashBigInt(params, d)}
	}

	// 2. Build all levels (from leaves up to the root)
	levels := buildAllLevels(params, leaves)
	// The root is the single element in the topmost level
	root := levels[len(levels)-1][0]

	return &MerkleTree{
		Root:   root,
		Levels: levels,
	}, nil
}

// buildAllLevels builds and returns a slice-of-slices representation of the Merkle tree.
// levels[0] = leaves level
// levels[1] = parents of leaves
// ...
// levels[n] = top level (root only if count>1)
func buildAllLevels(params *config.Params, level []*Node) [][]*Node {
	var levels [][]*Node
	levels = append(levels, level)

	// Keep building until we reach a single node in the topmost level.
	for len(level) > 1 {
		level = buildNextLevel(params, level)
		levels = append(levels, level)
	}
	return levels
}

// buildNextLevel takes a slice of Nodes (sibling pairs) and produces the parent level.
// If there's an odd leftover, we duplicate it. That ensures each level has an even length
// (unless it's length=1, in which case we've already reached the root).
func buildNextLevel(params *config.Params, nodes []*Node) []*Node {
	var parents []*Node

	// Combine siblings in pairs
	for i := 0; i < len(nodes); i += 2 {
		if i+1 < len(nodes) {
			// Normal case: combine node[i], node[i+1]
			combinedHash := HashData(params, [][]byte{
				nodes[i].Hash.Bytes(),
				nodes[i+1].Hash.Bytes(),
			})
			parents = append(parents, &Node{Hash: combinedHash})
		} else {
			// Odd leftover: duplicate the last node
			combinedHash := HashData(params, [][]byte{
				nodes[i].Hash.Bytes(),
				nodes[i].Hash.Bytes(),
			})
			parents = append(parents, &Node{Hash: combinedHash})
		}
	}

	return parents
}

// GetAuthenticationPath returns the sibling hashes on the path from
// leaf `index` up to (but not including) the root.
func (mt *MerkleTree) GetAuthenticationPath(params *config.Params, index int) ([]*big.Int, error) {
	if index < 0 || index >= len(mt.Levels[0]) {
		return nil, fmt.Errorf("index out of bounds")
	}

	var path []*big.Int

	// Walk from level 0 (the leaves) up to the top.
	// We use the precomputed mt.Levels so that sibling relationships are consistent.
	for level := 0; level < len(mt.Levels)-1; level++ {
		nodes := mt.Levels[level]
		// Sibling is the XOR of index with 1
		siblingIndex := index ^ 1

		if siblingIndex < len(nodes) {
			path = append(path, nodes[siblingIndex].Hash)
		} else {
			// If siblingIndex is out of range (we had an odd leftover
			// that was duplicated), just treat the sibling as the same node.
			path = append(path, nodes[index].Hash)
		}

		// Move up one level: integer divide index by 2
		index /= 2
	}

	return path, nil
}

// VerifyAuthenticationPath checks whether a proof is valid for a given leaf value
// (publicKey) against a Merkle root.  The `index` should match the original leaf index.
func VerifyAuthenticationPath(
	params *config.Params,
	publicKey *big.Int,
	path []*big.Int,
	root *big.Int,
	index int,
) bool {
	// Start with the leaf hash.
	hash := HashBigInt(params, publicKey)

	// Re-hash up the tree, combining with siblings in `path`.
	// If index is even => we are a "left" node => H( self, sibling ).
	// If index is odd  => we are a "right" node => H( sibling, self ).
	for _, siblingHash := range path {
		if index%2 == 0 {
			hash = HashData(params, [][]byte{
				hash.Bytes(),
				siblingHash.Bytes(),
			})
		} else {
			hash = HashData(params, [][]byte{
				siblingHash.Bytes(),
				hash.Bytes(),
			})
		}
		index /= 2
	}

	// Compare with the stored Merkle root
	return hash.Cmp(root) == 0
}
