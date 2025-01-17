package schnorr

import (
	"crypto/rand"
	"fmt"
	"hash"
	"math/big"
	"multisig/config"
	"multisig/utils"
)

// The private key, to sign a message and the public key, to verify the signature
type keyPair struct {
	privateKey *big.Int
	publicKey  *big.Int
}

// Result of the Schnorr signature is the pair (X, y)
type signature struct {
	X *big.Int
	y *big.Int
}

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

func sign(params *config.Params, privateKey *big.Int, message []byte) (*signature, error) {
	// Choose a random r (0 <= r <= q-1) as the secret key
	r, err := rand.Int(rand.Reader, params.Q)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random r: %v", err)
	}

	// Calculate commitment X = g^r mod p
	X := new(big.Int).Exp(params.G, r, params.P)

	// Calculate challenge e = H(X || message)
	e := utils.HashData(params, [][]byte{X.Bytes(), message})
	// e.Mod(e, params.q)

	// Calculate y = es + r mod q
	y := new(big.Int).Mul(e, privateKey)
	y.Add(y, r)
	y.Mod(y, params.Q)

	return &signature{X: X, y: y}, nil
}

func verify(params *config.Params, publicKey *big.Int, message []byte, sig *signature) bool {
	// Calculate e' = H(X' || message)
	e := utils.HashData(params, [][]byte{sig.X.Bytes(), message})

	// check whether g^y' =?= X' I^e'
	lhs := new(big.Int).Exp(params.G, sig.y, params.P)
	rhs := new(big.Int).Exp(publicKey, e, params.P)
	rhs.Mul(rhs, sig.X)
	rhs.Mod(rhs, params.P)

	return lhs.Cmp(rhs) == 0
}

func SchnorrDemo(bitLength int, hashFactory func() hash.Hash) {
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

	// Generate keys
	keys, err := generateKeyPair(params)
	if err != nil {
		// fmt.Println("failed to generate keys: %v", err)
		panic(err)
	}
	fmt.Println("Keys generated")
	fmt.Println("sk:", keys.privateKey)
	fmt.Println("pk:", keys.publicKey)

	// Message to sign
	message := []byte("Hello, Schnorr!")
	fmt.Println("Message:", string(message))

	// Sign the message
	sig, err := sign(params, keys.privateKey, message)
	if err != nil {
		// fmt.Println("failed to sign message: %v", err)
		panic(err)
	}
	fmt.Println("Message signed")
	fmt.Println("X:", sig.X)
	fmt.Println("y:", sig.y)

	// Verify the signature
	if verify(params, keys.publicKey, message, sig) {
		fmt.Println("Signature verified!")
	} else {
		fmt.Println("Signature verification failed.")
	}
}
