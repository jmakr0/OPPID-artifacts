#!/bin/sh

echo "Running benchmarks ..."

# Check if a command line argument is passed
RESULTS_FILE=${RESULTS_FILE:-benchmark_results.log}

# Other parameters: -count=5 -benchtime=10s
# Remark: The timeout has been set to 120 minutes as benchmarking the hash-based proofs (via a SNARK) takes a significant amount of time
go test -bench=. -timeout=120m -benchmem ./benchmark > "$RESULTS_FILE"

echo "Benchmarks completed. Results saved to $RESULTS_FILE"