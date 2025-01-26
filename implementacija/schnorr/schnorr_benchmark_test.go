package schnorr

import (
	"fmt"
	"hash"
	"log"
	"multisig/config"
	"os"
	"testing"
)

var (
	bitLength    int
	hashFactory  func() hash.Hash
	testNSigners []uint
)

// TestMain is the entry point for tests and benchmarks in this package.
func TestMain(m *testing.M) {
	// Load environment variables once
	var err error
	bitLength, hashFactory, _, testNSigners, err = config.LoadEnv("../.env")
	if err != nil {
		log.Fatalf("Failed to load environment configuration: %v", err)
	}

	// Run tests and benchmarks
	os.Exit(m.Run())
}

// BenchmarkKeyGeneration benchmarks the key generation process.
func BenchmarkKeyGeneration(b *testing.B) {
	for _, nSigners := range testNSigners {
		b.Run(fmt.Sprintf("nSigners=%d", nSigners), func(b *testing.B) {
			params, err := config.GenerateParameters(bitLength, hashFactory)
			if err != nil {
				b.Fatalf("Failed to generate parameters: %v", err)
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				for j := uint(0); j < nSigners; j++ {
					_, err := generateKeyPair(params)
					if err != nil {
						b.Fatalf("Failed to generate keys: %v", err)
					}
				}
			}
		})
	}
}

// BenchmarkSigning benchmarks the signing process.
func BenchmarkSigning(b *testing.B) {
	for _, nSigners := range testNSigners {
		b.Run(fmt.Sprintf("nSigners=%d", nSigners), func(b *testing.B) {
			params, err := config.GenerateParameters(bitLength, hashFactory)
			if err != nil {
				b.Fatalf("Failed to generate parameters: %v", err)
			}

			allKeys := make([]*keyPair, nSigners)
			for j := uint(0); j < nSigners; j++ {
				keys, err := generateKeyPair(params)
				if err != nil {
					b.Fatalf("Failed to generate keys: %v", err)
				}
				allKeys[j] = keys
			}

			message := []byte("Benchmark message for Schnorr signing")

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				for j := uint(0); j < nSigners; j++ {
					_, err := sign(params, allKeys[j].privateKey, message)
					if err != nil {
						b.Fatalf("Failed to sign message: %v", err)
					}
				}
			}
		})
	}
}

// BenchmarkVerification benchmarks the verification process.
func BenchmarkVerification(b *testing.B) {
	for _, nSigners := range testNSigners {
		b.Run(fmt.Sprintf("nSigners=%d", nSigners), func(b *testing.B) {
			params, err := config.GenerateParameters(bitLength, hashFactory)
			if err != nil {
				b.Fatalf("Failed to generate parameters: %v", err)
			}

			allKeys := make([]*keyPair, nSigners)
			allSigs := make([]*signature, nSigners)

			for j := uint(0); j < nSigners; j++ {
				keys, err := generateKeyPair(params)
				if err != nil {
					b.Fatalf("Failed to generate keys: %v", err)
				}
				allKeys[j] = keys
			}

			message := []byte("Benchmark message for Schnorr verification")

			for j := uint(0); j < nSigners; j++ {
				sig, err := sign(params, allKeys[j].privateKey, message)
				if err != nil {
					b.Fatalf("Failed to sign message: %v", err)
				}
				allSigs[j] = sig
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				for j := uint(0); j < nSigners; j++ {
					if !verify(params, allKeys[j].publicKey, message, allSigs[j]) {
						b.Fatalf("Failed to verify signature")
					}
				}
			}
		})
	}
}

// BenchmarkSchnorr benchmarks the entire Schnorr signature scheme.
func BenchmarkAll(b *testing.B) {
	for _, nSigners := range testNSigners {
		b.Run(fmt.Sprintf("nSigners=%d", nSigners), func(b *testing.B) {
			params, err := config.GenerateParameters(bitLength, hashFactory)
			if err != nil {
				b.Fatalf("Failed to generate parameters: %v", err)
			}

			allKeys := make([]*keyPair, nSigners)
			allSigs := make([]*signature, nSigners)

			message := []byte("Benchmark message")
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// Key generation
				for j := uint(0); j < nSigners; j++ {
					allKeys[j], err = generateKeyPair(params)
					if err != nil {
						b.Fatalf("Failed to generate keys: %v", err)
					}
				}

				// Signing
				for j := uint(0); j < nSigners; j++ {
					allSigs[j], err = sign(params, allKeys[j].privateKey, message)
					if err != nil {
						b.Fatalf("Failed to sign message: %v", err)
					}
				}

				// Verification
				for j := uint(0); j < nSigners; j++ {
					if !verify(params, allKeys[j].publicKey, message, allSigs[j]) {
						b.Fatalf("Failed to verify signature")
					}
				}
			}
		})
	}
}
