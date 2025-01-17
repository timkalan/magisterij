package schnorr

import (
	"hash"
	"log"
	"multisig/config"
	"os"
	"testing"
)

var (
	bitLength   int
	hashFactory func() hash.Hash
	nSigners    uint
)

// TestMain is the entry point for tests and benchmarks in this package.
func TestMain(m *testing.M) {
	// Load environment variables once
	var err error
	bitLength, hashFactory, nSigners, err = config.LoadEnv("../.env")
	if err != nil {
		log.Fatalf("Failed to load environment configuration: %v", err)
	}

	// Run tests and benchmarks
	os.Exit(m.Run())
}

// BenchmarkKeyGeneration benchmarks the key generation process.
func BenchmarkKeyGeneration(b *testing.B) {
	// Generate parameters once (not part of the benchmark)
	params, err := config.GenerateParameters(bitLength, hashFactory)
	if err != nil {
		b.Fatalf("Failed to generate parameters: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generateKeyPair(params)
		if err != nil {
			b.Fatalf("Failed to generate keys: %v", err)
		}
	}
}

// BenchmarkSigning benchmarks the signing process.
func BenchmarkSigning(b *testing.B) {
	// Generate parameters and key pair
	params, err := config.GenerateParameters(bitLength, hashFactory)
	if err != nil {
		b.Fatalf("Failed to generate parameters: %v", err)
	}
	keys, err := generateKeyPair(params)
	if err != nil {
		b.Fatalf("Failed to generate keys: %v", err)
	}

	message := []byte("Benchmark message for Schnorr signing")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := sign(params, keys.privateKey, message)
		if err != nil {
			b.Fatalf("Failed to sign message: %v", err)
		}
	}
}

// BenchmarkVerification benchmarks the verification process.
func BenchmarkVerification(b *testing.B) {
	// Generate parameters, key pair, and signature
	params, err := config.GenerateParameters(bitLength, hashFactory)
	if err != nil {
		b.Fatalf("Failed to generate parameters: %v", err)
	}
	keys, err := generateKeyPair(params)
	if err != nil {
		b.Fatalf("Failed to generate keys: %v", err)
	}
	message := []byte("Benchmark message for Schnorr verification")
	sig, err := sign(params, keys.privateKey, message)
	if err != nil {
		b.Fatalf("Failed to sign message: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if !verify(params, keys.publicKey, message, sig) {
			b.Fatalf("Failed to verify signature")
		}
	}
}

// BenchmarkSchnorr benchmarks signing and verifying with N_SIGNERS.
func BenchmarkSchnorr(b *testing.B) {
	// Generate parameters and key pairs for the signers
	params, _ := config.GenerateParameters(bitLength, hashFactory)
	keys := make([]*keyPair, nSigners)
	for i := uint(0); i < nSigners; i++ {
		keys[i], _ = generateKeyPair(params)
	}

	message := []byte("Benchmark message")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for j := 0; j < int(nSigners); j++ {
			sig, _ := sign(params, keys[j].privateKey, message)
			verify(params, keys[j].publicKey, message, sig)
		}
	}
}
