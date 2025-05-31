package main

import (
	"fmt"
	"multisig/asm"
	"multisig/config"
	"multisig/musig2"
	"multisig/schnorr"
)

func main() {

	bitLength, hash, nSigners, _, err := config.LoadEnv(".env")
	if err != nil {
		panic(err)
	}

	fmt.Println("\nSchnorr Signature Example")
	schnorr.SchnorrDemo(bitLength, hash)

	fmt.Println("\nASM Signature Example")
	asm.ASMDemo(bitLength, hash, nSigners)

	fmt.Println("\nMuSig2 Signature Example")
	musig2.MuSig2Demo(bitLength, hash, nSigners)
}
