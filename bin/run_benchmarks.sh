#!/bin/sh

echo "Running benchmarks ..."

# Other parameters: -count=5 -benchtime=10s
# Remark: The timeout has been set to 120 minutes as benchmarking the hash-based proofs (via a SNARK) takes a significant amount of time
go test -bench=. -timeout=120m -benchmem ./benchmark > benchmark_results.txt

echo "Benchmarks completed. Results saved to benchmark_results.txt"