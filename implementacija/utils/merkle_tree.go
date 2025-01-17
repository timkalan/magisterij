package utils

import (
	"fmt"
	"math/big"
	"multisig/config"
)

type Node struct {
	Hash  *big.Int
	Left  *Node
	Right *Node
}

type MerkleTree struct {
	Root   *Node
	Leaves []*Node
}

// NewMerkleTree constructs a Merkle tree from the given data.
func NewMerkleTree(params *config.Params, data []*big.Int) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("no data provided")
	}

	var leaves []*Node
	for _, d := range data {
		hash := HashBigInt(params, d)
		leaves = append(leaves, &Node{Hash: hash})
	}

	root := buildTree(params, leaves)
	return &MerkleTree{
		Root:   root,
		Leaves: leaves,
	}, nil
}

// buildTree recursively builds the Merkle tree.
func buildTree(params *config.Params, nodes []*Node) *Node {
	for len(nodes) > 1 {
		nodes = buildNextLevel(params, nodes)
	}
	return nodes[0]
}

// Helper function to build the next level of the tree
func buildNextLevel(params *config.Params, nodes []*Node) []*Node {
	var parents []*Node
	for i := 0; i < len(nodes); i += 2 {
		if i+1 < len(nodes) {
			combinedHash := HashData(params, [][]byte{nodes[i].Hash.Bytes(), nodes[i+1].Hash.Bytes()})
			parents = append(parents, &Node{Hash: combinedHash})
		} else {
			parents = append(parents, nodes[i]) // Promote the last node if odd count
		}
	}
	return parents
}

// GetAuthenticationPath generates the authentication path for a specific leaf.
func (mt *MerkleTree) GetAuthenticationPath(params *config.Params, index int) ([]*big.Int, error) {
	if index < 0 || index >= len(mt.Leaves) {
		return nil, fmt.Errorf("index out of bounds")
	}

	path := []*big.Int{}
	currentIndex := index
	nodes := mt.Leaves

	for len(nodes) > 1 {
		siblingIndex := currentIndex ^ 1 // Flip the last bit to find sibling
		if siblingIndex < len(nodes) {
			path = append(path, nodes[siblingIndex].Hash)
		}

		currentIndex /= 2                     // Move to parent index
		nodes = buildNextLevel(params, nodes) // Build the next level of the tree
	}

	return path, nil
}

// VerifyAuthenticationPath checks whether a proof is valid for a given public key and root.
func VerifyAuthenticationPath(
	params *config.Params,
	publicKey *big.Int,
	path []*big.Int,
	root *big.Int,
	index int,
) bool {
	hash := HashBigInt(params, publicKey)
	for _, p := range path {
		if index%2 == 0 {
			hash = HashData(params, [][]byte{hash.Bytes(), p.Bytes()})
		} else {
			hash = HashData(params, [][]byte{p.Bytes(), hash.Bytes()})
		}
		index /= 2
	}
	return hash.Cmp(root) == 0
}
