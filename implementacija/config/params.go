package config

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"
)

type Params struct {
	P *big.Int  // A large prime
	Q *big.Int  // A large prime factor of p-1
	G *big.Int  // A generator of the subgroup or order q in Z_p
	H hash.Hash // A hash function
}

// Generate a large prime q, find p via p = kq+1 and then find generator g
func GenerateParameters(bitLength int) (*Params, error) {
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

	return &Params{P: p, Q: q, G: g, H: sha256.New()}, nil
}
