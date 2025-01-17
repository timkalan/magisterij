package asm

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
	keys, err := generateKeys(params, 1024)
	if err != nil {
		b.Fatalf("failed to generate keys: %v", err)
	}

	message := []byte("Benchmark message for Schnorr signing")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := sign(params, keys, message, 1024)
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
	keys, err := generateKeys(params, 1024)
	if err != nil {
		b.Fatalf("failed to generate keys: %v", err)
	}
	message := []byte("Benchmark message for Schnorr verification")
	sig, err := sign(params, keys, message, 1024)
	if err != nil {
		b.Fatalf("failed to sign message: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		valid, err := verify(params, keys, message, sig, 1024)
		if err != nil {
			panic(err)
		}

		if !valid {
			b.Fatalf("failed to verify signature")
		}
	}
}

func BenchmarkASM(b *testing.B) {
	params, _ := config.GenerateParameters(1024)
	keys, _ := generateKeys(params, 1024)
	message := []byte("Benchmark message for ASM signing")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sig, _ := sign(params, keys, message, 1024)
		valid, err := verify(params, keys, message, sig, 1024)
		if err != nil {
			panic(err)
		}
		if !valid {
			b.Fatalf("failed to verify signature")
		}
	}
}
