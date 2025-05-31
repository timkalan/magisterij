package asm

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"hash"
	"math/big"
	"multisig/config"
	"multisig/utils"
)

// The private key, to sign a message and the public key, to verify the signature.
// Each signer has their own pair.
type keyPair struct {
	privateKey     *big.Int
	publicKey      *big.Int
	merkleTreePath []*big.Int
}

// Result of the ASM signature is the pair (X, y)
type signature struct {
	X *big.Int
	y *big.Int
}

// Generates key pair for one individual signer.
func generateKeyPair(params *config.Params) (*keyPair, error) {
	// Choose a random s (0 <= s <= q-1) as the secret key
	s, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random s: %v", err)
	}

	// Calculate I = g^s mod p as the public key
	I := new(big.Int).Exp(params.G, s, params.P)

	return &keyPair{privateKey: s, publicKey: I}, nil
}

// Generates all key pairs for all signers. Also prevents attack on key generation by providing
// and checking ZKPoK for all private keys.
func generateKeys(params *config.Params, nSigners uint) ([]*keyPair, error) {
	// Data that needs to be shared or remembered
	keys := make([]*keyPair, nSigners)
	commitments := make([]*big.Int, nSigners)
	rs := make([]*big.Int, nSigners)
	ys := make([]*big.Int, nSigners)

	// Each signer generates a standard Schnorr key pair
	for i := range nSigners {
		pair, err := generateKeyPair(params)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key pair: %v", err)
		}
		keys[i] = pair
	}

	// Each signer generates a commitment
	for i := range nSigners {
		// Choose a random r (0 <= r <= q-1)
		r, err := rand.Int(rand.Reader, params.Q)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random s: %v", err)
		}

		rs[i] = r

		// Calculate X = g^r mod p as the commitment
		X := new(big.Int).Exp(params.G, r, params.P)

		commitments[i] = X
	}

	// Each signer calculates the joint challenge e = H(X_1 || I_1 || ... || X_L || I_L)
	var buffer bytes.Buffer
	for i := range nSigners {
		buffer.Write(commitments[i].Bytes())
		buffer.Write(keys[i].publicKey.Bytes())
	}
	e := utils.HashData(params, [][]byte{buffer.Bytes()})

	// We actually need to use H3 here, so we take the most significant 100 bits
	e = new(big.Int).Rsh(e, uint(e.BitLen()-100))

	// Each signer calculates y_i = e s_i + r_i
	for i := range nSigners {
		y := new(big.Int).Mul(e, keys[i].privateKey)
		y.Add(y, rs[i])
		y.Mod(y, params.Q)

		ys[i] = y
	}

	// Each signer checks validity of all received Schnorr ZKPoK
	for j := range nSigners {
		// check whether g^y_j =?= X_j I_j^e
		lhs := new(big.Int).Exp(params.G, ys[j], params.P)
		rhs := new(big.Int).Exp(keys[j].publicKey, e, params.P)
		rhs.Mul(rhs, commitments[j])
		rhs.Mod(rhs, params.P)

		if lhs.Cmp(rhs) != 0 {
			return nil, fmt.Errorf("the ZKPoK is not valid: %d", j)
		}
	}

	// Each signer calculates Merkle tree root, includes it in public key
	// NOTE: the H4 hash function should be used here
	publicKeys := make([]*big.Int, nSigners)
	for i := range nSigners {
		publicKeys[i] = keys[i].publicKey
	}

	merkleTree, err := utils.NewMerkleTree(params, publicKeys)
	if err != nil {
		return nil, fmt.Errorf("failed generating Merkle tree: %v", err)
	}

	for i := range nSigners {
		path, err := merkleTree.GetAuthenticationPath(params, int(i))
		if err != nil {
			return nil, fmt.Errorf("failed getting authentication path: %v", err)
		}
		keys[i].merkleTreePath = path
	}

	return keys, nil
}

func sign(
	params *config.Params,
	keys []*keyPair,
	message []byte,
	nSigners uint) (*signature, error) {
	commitments := make([]*big.Int, nSigners)
	rs := make([]*big.Int, nSigners)
	ys := make([]*big.Int, nSigners)

	for i := range nSigners {
		// Each signer chooses a random r (0 <= r <= q-1)
		r, err := rand.Int(rand.Reader, params.Q)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random s: %v", err)
		}

		rs[i] = r

		// Calculate X = g^r mod p as the commitment
		X := new(big.Int).Exp(params.G, r, params.P)

		commitments[i] = X
	}

	// D calculates the joint commitment X = X_1 ... X_L mod p
	X := big.NewInt(1)
	for i := range nSigners {
		X.Mul(X, commitments[i])
	}
	X.Mod(X, params.P)

	// Each signer calculates e = H5(X || message || S)
	var buffer bytes.Buffer
	buffer.Write(X.Bytes())
	buffer.Write(message)
	// Represent S via all public keys
	for i := range nSigners {
		buffer.Write(keys[i].publicKey.Bytes())
	}
	e := utils.HashData(params, [][]byte{buffer.Bytes()})

	// Take the most significant 100 bits
	e = new(big.Int).Rsh(e, uint(e.BitLen()-100))

	// Each signer calculates y_i = e s_i + r_i
	for i := range nSigners {
		y := new(big.Int).Mul(e, keys[i].privateKey)
		y.Add(y, rs[i])
		y.Mod(y, params.Q)

		ys[i] = y
	}

	// D calculates y = y_1 + ... + y_L mod q and returns signature (X, y)
	y := big.NewInt(0)
	for i := range nSigners {
		y.Add(y, ys[i])
	}
	y.Mod(y, params.Q)

	return &signature{X: X, y: y}, nil
}

func verify(params *config.Params, keys []*keyPair, message []byte, sig *signature, nSigners uint) (bool, error) {
	// Check that all Merkle tree roots are the same
	publicKeys := make([]*big.Int, nSigners)
	for i := range nSigners {
		publicKeys[i] = keys[i].publicKey
	}

	merkleTree, err := utils.NewMerkleTree(params, publicKeys)
	if err != nil {
		return false, fmt.Errorf("failed generating Merkle tree: %v", err)
	}

	for i := range nSigners {
		if !utils.VerifyAuthenticationPath(
			params,
			keys[i].publicKey,
			keys[i].merkleTreePath,
			merkleTree.Root.Hash,
			int(i),
		) {
			fmt.Println("Failed to verify authentication path")
			return false, nil
		}
	}

	// Calculate I = I_1 ... I_L mod p
	I := big.NewInt(1)
	for i := range nSigners {
		I.Mul(I, keys[i].publicKey)
	}
	I.Mod(I, params.P)

	// Calculate e = H5(X || message || S)
	var buffer bytes.Buffer
	buffer.Write(sig.X.Bytes())
	buffer.Write(message)
	// Represent S via all public keys
	for i := range nSigners {
		buffer.Write(keys[i].publicKey.Bytes())
	}
	e := utils.HashData(params, [][]byte{buffer.Bytes()})

	// Take the most significant 100 bits
	e = new(big.Int).Rsh(e, uint(e.BitLen()-100))

	// Check whether g^y =?= X I^e
	lhs := new(big.Int).Exp(params.G, sig.y, params.P)
	rhs := new(big.Int).Exp(I, e, params.P)
	rhs.Mul(rhs, sig.X)
	rhs.Mod(rhs, params.P)

	return lhs.Cmp(rhs) == 0, nil
}

func ASMDemo(bitLength int, hashFactory func() hash.Hash, nSigners uint) {
	// Generate parameters
	params, err := config.GenerateParameters(bitLength, hashFactory)
	if err != nil {
		// fmt.Println("failed to generate parameters: %v", err)
		panic(err)
	}
	fmt.Println("Params generated")
	fmt.Println("p:", params.P)
	fmt.Println("q:", params.Q)
	fmt.Println("g:", params.G)

	fmt.Println("Number of signers:", nSigners)

	// Generate keys
	keys, err := generateKeys(params, nSigners)
	if err != nil {
		// fmt.Println("failed to generate keys: %v", err)
		panic(err)
	}
	fmt.Println("Keys generated")

	// Message to sign
	message := []byte("Hello, Accountable-Subgroup Multisignatures!")
	fmt.Println("Message:", string(message))

	// Sign the message
	sig, err := sign(params, keys, message, nSigners)
	if err != nil {
		// fmt.Println("failed to sign message: %v", err)
		panic(err)
	}
	fmt.Println("Message signed")
	fmt.Println("X:", sig.X)
	fmt.Println("y:", sig.y)

	// Verify the signature
	valid, err := verify(params, keys, message, sig, nSigners)
	if err != nil {
		panic(err)
	}
	if valid {
		fmt.Println("Signature verified!")
	} else {
		fmt.Println("Signature verification failed.")
	}
}
