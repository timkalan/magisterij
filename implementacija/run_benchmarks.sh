#!/bin/bash

SCHNORR_RESULTS="results/bench_schnorr.txt"
ASM_RESULTS="results/bench_asm.txt"

mkdir -p results

echo "Running Schnorr benchmarks..."
go test -bench=. -count=6 ./schnorr | tee $SCHNORR_RESULTS

echo "Running ASM benchmarks..."
go test -bench=. -count=6 ./asm | tee $ASM_RESULTS

# Clean up results for benchstat
sed -i '' 's/schnorr/asm/g' $SCHNORR_RESULTS

# Compare the results with benchstat
echo "Comparing results with benchstat:"
benchstat $SCHNORR_RESULTS $ASM_RESULTS
