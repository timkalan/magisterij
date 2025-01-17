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
	if len(nodes) == 1 {
		return nodes[0]
	}

	var parents []*Node
	for i := 0; i < len(nodes); i += 2 {
		if i+1 < len(nodes) {
			combinedHash := HashData(params, [][]byte{nodes[i].Hash.Bytes(), nodes[i+1].Hash.Bytes()})
			parents = append(parents, &Node{
				Hash:  combinedHash,
				Left:  nodes[i],
				Right: nodes[i+1],
			})
		} else {
			// Handle odd nodes by promoting the last node.
			parents = append(parents, nodes[i])
		}
	}

	return buildTree(params, parents)
}

// Helper function to find the parent of a node.
func findParent(node, root *Node) *Node {
	if root == nil || root.Left == nil && root.Right == nil {
		return nil
	}

	if root.Left == node || root.Right == node {
		return root
	}

	if left := findParent(node, root.Left); left != nil {
		return left
	}
	return findParent(node, root.Right)
}

// GetAuthenticationPath generates the authentication path for a specific leaf.
func (mt *MerkleTree) GetAuthenticationPath(index int) ([]*big.Int, error) {
	if index < 0 || index >= len(mt.Leaves) {
		return nil, fmt.Errorf("index out of bounds")
	}

	var path []*big.Int
	current := mt.Leaves[index]

	// Navigate up the tree and record sibling hashes.
	for current != mt.Root {
		parent := findParent(current, mt.Root)
		if parent == nil {
			break
		}

		if parent.Left == current {
			if parent.Right != nil {
				path = append(path, parent.Right.Hash)
			}
		} else {
			path = append(path, parent.Left.Hash)
		}
		current = parent
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
