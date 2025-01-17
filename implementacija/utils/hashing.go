package utils

import (
	"math/big"
	"multisig/config"
)

func HashBigInt(params *config.Params, number *big.Int) *big.Int {
	params.H.Reset()
	params.H.Write(number.Bytes())
	return new(big.Int).SetBytes(params.H.Sum(nil))
}

func HashData(params *config.Params, numbers [][]byte) *big.Int {
	params.H.Reset()
	for _, number := range numbers {
		params.H.Write(number)
	}
	return new(big.Int).SetBytes(params.H.Sum(nil))
}
