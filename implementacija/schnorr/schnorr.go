package schnorr

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"
)

// The parameters, usually found on the internet and not set by hand
type schnorrParams struct {
	p *big.Int  // A large prime
	q *big.Int  // A large prime factor of p-1
	g *big.Int  // A generator of the subgroup or order q in Z_p
	H hash.Hash // A hash function
}

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

// Generate a large prime q, find p via p = kq+1 and then find generator g
func generateParameters(bitLength int) (*schnorrParams, error) {
	// Step 1: Generate a large prime q
	q, err := rand.Prime(rand.Reader, bitLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prime q: %v", err)
	}

	// Step 2: Compute p = kq + 1
	var p *big.Int
	k := big.NewInt(1)
	one := big.NewInt(1)

	for {
		p = new(big.Int).Mul(q, k)
		p.Add(p, one)            // p = kq + 1
		if p.ProbablyPrime(20) { // Check if p is prime
			break
		}
		k.Add(k, one) // Increment k
	}

	// Step 3: Find a generator g
	var g *big.Int
	for {
		h, err := rand.Int(rand.Reader, p)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random h: %v", err)
		}
		// g = h^((p-1)/q) mod p
		g = new(big.Int).Exp(h, new(big.Int).Div(new(big.Int).Sub(p, one), q), p)
		if g.Cmp(one) != 0 {
			break
		}
	}

	return &schnorrParams{p: p, q: q, g: g, H: sha256.New()}, nil
}

func generateKeyPair(params *schnorrParams) (*keyPair, error) {
	// Choose a random s (0 <= s <= q-1) as the secret key
	s, err := rand.Int(rand.Reader, params.q)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random s: %v", err)
	}

	// Calculate I = g^s mod p as the public key
	I := new(big.Int).Exp(params.g, s, params.p)

	return &keyPair{privateKey: s, publicKey: I}, nil
}

func sign(params *schnorrParams, privateKey *big.Int, message []byte) (*signature, error) {
	// Choose a random r (0 <= r <= q-1) as the secret key
	r, err := rand.Int(rand.Reader, params.q)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random r: %v", err)
	}

	// Calculate commitment X = g^r mod p
	X := new(big.Int).Exp(params.g, r, params.p)

	// Calculate challenge e = H(X || message)
	params.H.Reset()
	params.H.Write(X.Bytes())
	params.H.Write(message)
	e := new(big.Int).SetBytes(params.H.Sum(nil))
	// e.Mod(e, params.q)

	// Calculate y = es + r mod q
	y := new(big.Int).Mul(e, privateKey)
	y.Add(y, r)
	y.Mod(y, params.q)

	return &signature{X: X, y: y}, nil
}

func verify(params *schnorrParams, publicKey *big.Int, message []byte, sig *signature) bool {
	// Calculate e' = H(X' || message)
	params.H.Reset()
	params.H.Write(sig.X.Bytes())
	params.H.Write(message)
	e := new(big.Int).SetBytes(params.H.Sum(nil))

	// check whether g^y' =?= X' I^e'
	lhs := new(big.Int).Exp(params.g, sig.y, params.p)
	rhs := new(big.Int).Exp(publicKey, e, params.p)
	rhs.Mul(rhs, sig.X)
	rhs.Mod(rhs, params.p)

	fmt.Println("lhs:", lhs)
	fmt.Println("rhs:", rhs)

	return lhs.Cmp(rhs) == 0
}

func SchnorrDemo() {
	// Generate parameters
	params, err := generateParameters(512)
	if err != nil {
		// fmt.Println("failed to generate parameters: %v", err)
		panic(err)
	}
	fmt.Println("Params generated")
	fmt.Println("p:", params.p)
	fmt.Println("q:", params.q)
	fmt.Println("g:", params.g)

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
