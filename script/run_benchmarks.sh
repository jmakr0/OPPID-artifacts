#!/bin/bash

echo "Running benchmarks..."

go test -bench=. -benchmem ./benchmark > benchmark_results.txt

echo "Benchmarks completed. Results saved to benchmark_results.txt."