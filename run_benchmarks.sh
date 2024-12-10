#!/bin/sh

echo "Running benchmarks ..."

RESULTS_FILE=${1:-benchmark_results.log}

# Other parameters: -count=5 -benchtime=10s
# The timeout has been set to 120 minutes as benchmarking the hash-based proofs (via a SNARK) takes a significant amount of time
go test -bench=. -timeout=120m -benchmem ./benchmark/... > "$RESULTS_FILE"

echo "Benchmarks completed. Results saved to $RESULTS_FILE"