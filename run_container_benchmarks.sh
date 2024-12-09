#!/bin/sh

echo "Build container ..."

docker build -t pets25-oppid .

echo "Execute container ..."
docker run --name oppid-bench --volume ./benchmark:/oppid/benchmark  pets25-oppid

echo "Retrieve results ..."
docker rm oppid-bench

echo "Results stored at benchmark/benchmark_results.txt"
