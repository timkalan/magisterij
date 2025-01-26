package config

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Params struct {
	P           *big.Int         // A large prime
	Q           *big.Int         // A large prime factor of p-1
	G           *big.Int         // A generator of the subgroup or order q in Z_p
	HashFactory func() hash.Hash // A hash function
}

// LoadEnv loads configuration parameters from a .env file
func LoadEnv(path string) (int, func() hash.Hash, uint, []uint, error) {
	// Load the .env file
	if err := godotenv.Load(path); err != nil {
		return 0, nil, 0, nil, errors.New("failed to load .env file")
	}

	// Get BIT_LENGTH
	bitLengthStr := os.Getenv("BIT_LENGTH")
	bitLength, err := strconv.Atoi(bitLengthStr)
	if err != nil {
		return 0, nil, 0, nil, errors.New("invalid BIT_LENGTH: must be an integer")
	}

	// Get HASH_FUNCTION
	hashFunction := os.Getenv("HASH_FUNCTION")
	var hashFactory func() hash.Hash
	switch hashFunction {
	case "sha256":
		hashFactory = sha256.New
	case "sha512":
		hashFactory = sha512.New
	default:
		return 0, nil, 0, nil, errors.New("invalid HASH_FUNCTION: must be 'sha256' or 'sha512'")
	}
	// Get N_SIGNERS
	nSignersStr := os.Getenv("N_SIGNERS")
	nSigners, err := strconv.Atoi(nSignersStr)
	if err != nil {
		return 0, nil, 0, nil, errors.New("invalid N_SIGNERS: must be an integer")
	}

	testNSigners := []uint{}

	// Get BENCHMARK_SIGNERS=1,2,4,8,16,32
	benchmarkSignersStr := os.Getenv("BENCHMARK_SIGNERS")
	// BENCHMARK_SIGNERS is a comma-separated list of integers
	benchmarkSigners := strings.Split(benchmarkSignersStr, ",")
	for _, s := range benchmarkSigners {
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, nil, 0, nil, errors.New("invalid BENCHMARK_SIGNERS: must be a comma-separated list of integers")
		}
		testNSigners = append(testNSigners, uint(n))
	}

	return bitLength, hashFactory, uint(nSigners), testNSigners, nil
}

// Generate a large prime q, find p via p = kq+1 and then find generator g
func GenerateParameters(bitLength int, hashFactory func() hash.Hash) (*Params, error) {
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

	return &Params{P: p, Q: q, G: g, HashFactory: hashFactory}, nil
}
