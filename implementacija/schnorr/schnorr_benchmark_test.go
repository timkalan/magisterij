package schnorr

import (
	"multisig/config"
	"testing"
)

// BenchmarkKeyGeneration benchmarks the key generation process
func BenchmarkKeyGeneration(b *testing.B) {
	// Generate parameters once, as it's not part of the benchmark
	params, err := config.GenerateParameters(1024)
	if err != nil {
		b.Fatalf("failed to generate parameters: %v", err)
	}

	b.ResetTimer() // Reset the timer to ignore setup time

	for i := 0; i < b.N; i++ {
		_, err := generateKeyPair(params)
		if err != nil {
			b.Fatalf("failed to generate keys: %v", err)
		}
	}
}

// BenchmarkSigning benchmarks the signing process
func BenchmarkSigning(b *testing.B) {
	// Generate parameters and key pair
	params, err := config.GenerateParameters(1024)
	if err != nil {
		b.Fatalf("failed to generate parameters: %v", err)
	}
	keys, err := generateKeyPair(params)
	if err != nil {
		b.Fatalf("failed to generate keys: %v", err)
	}

	message := []byte("Benchmark message for Schnorr signing")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := sign(params, keys.privateKey, message)
		if err != nil {
			b.Fatalf("failed to sign message: %v", err)
		}
	}
}

// BenchmarkVerification benchmarks the verification process
func BenchmarkVerification(b *testing.B) {
	// Generate parameters, key pair, and signature
	params, err := config.GenerateParameters(1024)
	if err != nil {
		b.Fatalf("failed to generate parameters: %v", err)
	}
	keys, err := generateKeyPair(params)
	if err != nil {
		b.Fatalf("failed to generate keys: %v", err)
	}
	message := []byte("Benchmark message for Schnorr verification")
	sig, err := sign(params, keys.privateKey, message)
	if err != nil {
		b.Fatalf("failed to sign message: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if !verify(params, keys.publicKey, message, sig) {
			b.Fatalf("failed to verify signature")
		}
	}
}

func BenchmarkSchnorr(b *testing.B) {
	params, _ := config.GenerateParameters(1024)
	keys := make([]*keyPair, 1000) // Simulate keys for up to 1000 signers
	for i := 0; i < 1000; i++ {
		keys[i], _ = generateKeyPair(params)
	}

	message := []byte("Benchmark message")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ { // Simulate 100 individual signatures
			sig, _ := sign(params, keys[j].privateKey, message)
			verify(params, keys[j].publicKey, message, sig)
		}
	}
}
