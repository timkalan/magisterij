#!/bin/bash

SCHNORR_RESULTS="results/bench_Schnorr.txt"
ASM_RESULTS="results/bench_ASM.txt"
MUSIG2_RESULTS="results/bench_MuSig2.txt"
BENCHMARKS="."
RUNS=6

# Benchmarks is the first argument, runs is the second
if [ $# -eq 2 ]; then
    BENCHMARKS=$1
    RUNS=$2
fi

mkdir -p results

echo "Running Schnorr benchmarks..."
go test -bench=$BENCHMARKS -count=$RUNS -timeout=0 ./schnorr | tee $SCHNORR_RESULTS

echo "Running ASM benchmarks..."
go test -bench=$BENCHMARKS -count=$RUNS -timeout=0 ./asm | tee $ASM_RESULTS

echo "Running MuSig2 benchmarks..."
go test -bench=$BENCHMARKS -count=$RUNS -timeout=0 ./musig2 | tee $MUSIG2_RESULTS

# Clean up results for benchstat
sed -i '' 's/schnorr/asm/g' $SCHNORR_RESULTS
sed -i '' 's/musig2/asm/g' $MUSIG2_RESULTS

# Compare the results with benchstat
echo "Comparing results with benchstat:"
benchstat $SCHNORR_RESULTS $ASM_RESULTS $MUSIG2_RESULTS
