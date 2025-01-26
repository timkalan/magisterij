package asm

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

// BenchmarkKeyGeneration measures the time taken to generate a key pair.
func BenchmarkKeyGeneration(b *testing.B) {

	for _, nSigners := range testNSigners {
		b.Run("nSigners="+fmt.Sprint(nSigners), func(b *testing.B) {
			params, err := config.GenerateParameters(bitLength, hashFactory)
			if err != nil {
				b.Fatalf("failed to generate parameters: %v", err)
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := generateKeys(params, nSigners)
				if err != nil {
					b.Fatalf("failed to generate keys: %v", err)
				}
			}
		})
	}
}

// BenchmarkSigning measures the time taken to sign a message.
func BenchmarkSigning(b *testing.B) {

	for _, nSigners := range testNSigners {
		b.Run("nSigners="+fmt.Sprint(nSigners), func(b *testing.B) {
			params, err := config.GenerateParameters(bitLength, hashFactory)
			if err != nil {
				b.Fatalf("failed to generate parameters: %v", err)
			}
			keys, err := generateKeys(params, nSigners)
			if err != nil {
				b.Fatalf("failed to generate keys: %v", err)
			}

			message := []byte("Benchmark message for Schnorr signing")

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := sign(params, keys, message, nSigners)
				if err != nil {
					b.Fatalf("failed to sign message: %v", err)
				}
			}
		})
	}
}

// BenchmarkVerification measures the time taken to verify a signature.
func BenchmarkVerification(b *testing.B) {

	for _, nSigners := range testNSigners {
		b.Run("nSigners="+fmt.Sprint(nSigners), func(b *testing.B) {
			params, err := config.GenerateParameters(bitLength, hashFactory)
			if err != nil {
				b.Fatalf("failed to generate parameters: %v", err)
			}
			keys, err := generateKeys(params, nSigners)
			if err != nil {
				b.Fatalf("failed to generate keys: %v", err)
			}
			message := []byte("Benchmark message for Schnorr verification")
			sig, err := sign(params, keys, message, nSigners)
			if err != nil {
				b.Fatalf("failed to sign message: %v", err)
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				valid, err := verify(params, keys, message, sig, nSigners)
				if err != nil {
					b.Fatalf("failed to verify signature: %v", err)
				}
				if !valid {
					b.Fatalf("failed to verify signature")
				}
			}
		})
	}
}

// BenchmarkASM measures the time taken to generate keys, sign a message, and verify the signature.
func BenchmarkAll(b *testing.B) {

	for _, nSigners := range testNSigners {
		b.Run("nSigners="+fmt.Sprint(nSigners), func(b *testing.B) {
			params, err := config.GenerateParameters(bitLength, hashFactory)
			if err != nil {
				b.Fatalf("failed to generate parameters: %v", err)
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				keys, err := generateKeys(params, nSigners)
				if err != nil {
					b.Fatalf("failed to generate keys: %v", err)
				}
				message := []byte("Benchmark message for ASM signing")

				sig, err := sign(params, keys, message, nSigners)
				if err != nil {
					b.Fatalf("failed to sign message: %v", err)
				}

				valid, err := verify(params, keys, message, sig, nSigners)
				if err != nil {
					b.Fatalf("failed to verify signature: %v", err)
				}
				if !valid {
					b.Fatalf("failed to verify signature")
				}
			}
		})
	}
}
