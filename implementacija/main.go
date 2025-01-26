package main

import (
	"fmt"
	"multisig/asm"
	"multisig/config"
	"multisig/schnorr"
)

func main() {

	bitLength, hash, nSigners, _, err := config.LoadEnv(".env")
	if err != nil {
		panic(err)
	}

	fmt.Println("Schnorr Signature Example")
	schnorr.SchnorrDemo(bitLength, hash)

	fmt.Println("ASM Signature Example")
	asm.ASMDemo(bitLength, hash, nSigners)
}
