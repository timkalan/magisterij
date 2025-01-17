package utils

import (
	"math/big"
	"multisig/config"
)

// HashBigInt hashes a single big.Int using the hash function provided in params.
func HashBigInt(params *config.Params, number *big.Int) *big.Int {
	h := params.HashFactory() // Create a new hash instance
	h.Write(number.Bytes())
	return new(big.Int).SetBytes(h.Sum(nil))
}

// HashData hashes multiple byte slices by concatenating them and applying the hash function.
func HashData(params *config.Params, numbers [][]byte) *big.Int {
	h := params.HashFactory() // Create a new hash instance
	for _, number := range numbers {
		h.Write(number)
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}
