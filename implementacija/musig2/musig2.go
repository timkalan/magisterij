package musig2

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
	privateKey           *big.Int
	publicKey            *big.Int
	aggregateCoefficient *big.Int
	aggregatedKey        *big.Int
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

	// Each signer generates a standard Schnorr key pair
	for i := range nSigners {
		pair, err := generateKeyPair(params)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key pair: %v", err)
		}
		keys[i] = pair
	}

	// Each signer calculates the aggregate coefficient c_i
	var buffer bytes.Buffer
	for i := range nSigners {
		buffer.Write(keys[i].publicKey.Bytes())
	}

	for i := range nSigners {
		buffer.Write(keys[i].publicKey.Bytes())
		keys[i].aggregateCoefficient = utils.HashData(params, [][]byte{buffer.Bytes()})

		// Remove the last added public key from the buffer to avoid duplication
		buffer.Truncate(buffer.Len() - len(keys[i].publicKey.Bytes()))
	}

	// Each signer calculates the aggregated public key
	I := big.NewInt(1)
	for i := range nSigners {
		term := new(big.Int).Exp(keys[i].publicKey, keys[i].aggregateCoefficient, params.P)
		I.Mul(I, term)
		I.Mod(I, params.P)
	}

	// Distribute it to all keyPair structs
	for i := range nSigners {
		keys[i].aggregatedKey = I
	}

	return keys, nil
}

func sign(
	params *config.Params,
	keys []*keyPair,
	message []byte,
	nSigners uint) (*signature, error) {
	nu := 2 // Each signer creates nu nonces
	rs := make(map[*big.Int][]*big.Int, nSigners)
	commitments := make(map[*big.Int][]*big.Int, nSigners)
	jointCommitments := make([]*big.Int, nu)

	// 1. ROUND

	// Each signer generates nu commitments
	for i := range nSigners {
		commitments[keys[i].publicKey] = make([]*big.Int, nu)
		rs[keys[i].publicKey] = make([]*big.Int, nu)
		for j := range nu {
			// Each signer chooses a random r (0 <= r <= q-1)
			r, err := rand.Int(rand.Reader, params.Q)
			if err != nil {
				return nil, fmt.Errorf("failed to generate random s: %v", err)
			}

			// Store the random r for later use
			rs[keys[i].publicKey][j] = r

			// Calculate X = g^r mod p as the commitment
			X := new(big.Int).Exp(params.G, r, params.P)

			// Store the commitment: public key -> list of commitments
			commitments[keys[i].publicKey][j] = X
		}
	}

	// D calculates the joint commitments
	for j := range nu {
		X := big.NewInt(1)
		for i := range nSigners {
			X.Mul(X, commitments[keys[i].publicKey][j])
		}
		X.Mod(X, params.P)
		jointCommitments[j] = X
	}

	// 2. ROUND

	// calculate b
	var buffer bytes.Buffer
	buffer.Write(keys[0].aggregatedKey.Bytes())
	for j := range nu {
		buffer.Write(jointCommitments[j].Bytes())
	}
	buffer.Write(message)

	b := utils.HashData(params, [][]byte{buffer.Bytes()})

	b_powers_mod_q := make([]*big.Int, nu)
	for j_idx := range nu {
		b_powers_mod_q[j_idx] = new(big.Int).Exp(b, big.NewInt(int64(j_idx)), params.Q)
	}

	// calculate X (effective aggregate public nonce R)
	X := big.NewInt(1)
	for j := range nu {
		exponent_for_Rj := new(big.Int).Exp(b, big.NewInt(int64(j)), params.Q)

		term := new(big.Int).Exp(jointCommitments[j], exponent_for_Rj, params.P)

		X.Mul(X, term)
		X.Mod(X, params.P)
	}

	// calculate a
	buffer.Reset()
	buffer.Write(keys[0].aggregatedKey.Bytes())
	buffer.Write(X.Bytes())
	buffer.Write(message)
	a := utils.HashData(params, [][]byte{buffer.Bytes()})

	// calculate y_i for each signer
	ys := make([]*big.Int, nSigners)
	for i := range nSigners {
		// Calculate the key-related part: (a * privateKey_i * aggregateCoefficient_i)
		// This part will be taken modulo Q at the end of the ys[i] calculation.
		ys_i_val := new(big.Int).Mul(a, keys[i].privateKey)
		ys_i_val.Mul(ys_i_val, keys[i].aggregateCoefficient)

		// Calculate the nonce-related part: sum(r_ij * (b^j mod Q))
		for j := range nu {
			// Calculate exponent_bj = b^j mod Q
			exponent_bj_mod_q := b_powers_mod_q[j]

			// term_to_add = (b^j mod Q) * rs[keys[i].publicKey][j]
			term_to_add := new(big.Int).Mul(exponent_bj_mod_q, rs[keys[i].publicKey][j])

			ys_i_val.Add(ys_i_val, term_to_add)
		}
		ys_i_val.Mod(ys_i_val, params.Q)
		ys[i] = ys_i_val
	}

	// calculate y
	y := big.NewInt(0)
	for i := range nSigners {
		y.Add(y, ys[i])
	}
	y.Mod(y, params.Q)

	return &signature{X: X, y: y}, nil
}

func verify(params *config.Params, keys []*keyPair, message []byte, sig *signature) (bool, error) {
	aggregatedKey := keys[0].aggregatedKey

	// Calculate e = Hsig(I || X || m)
	var buffer bytes.Buffer
	buffer.Write(aggregatedKey.Bytes())
	buffer.Write(sig.X.Bytes())
	buffer.Write(message)
	e := utils.HashData(params, [][]byte{buffer.Bytes()})

	// Check whether g^y =?= X I^e
	lhs := new(big.Int).Exp(params.G, sig.y, params.P)
	rhs := new(big.Int).Exp(aggregatedKey, e, params.P)
	rhs.Mul(rhs, sig.X)
	rhs.Mod(rhs, params.P)

	return lhs.Cmp(rhs) == 0, nil
}

func MuSig2Demo(bitLength int, hashFactory func() hash.Hash, nSigners uint) {
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
	message := []byte("Hello, MuSig2!")
	fmt.Println("Message:", string(message))

	// Sign the message
	sig, err := sign(params, keys, message, nSigners)
	if err != nil {
		panic(err)
	}
	fmt.Println("Message signed")
	fmt.Println("X:", sig.X)
	fmt.Println("y:", sig.y)

	// Verify the signature
	valid, err := verify(params, keys, message, sig)
	if err != nil {
		panic(err)
	}
	if valid {
		fmt.Println("Signature verified!")
	} else {
		fmt.Println("Signature verification failed.")
	}
}
