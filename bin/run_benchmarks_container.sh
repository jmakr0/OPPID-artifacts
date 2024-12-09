#!/bin/sh

RESULTS_FILE=${RESULTS_FILE:-benchmark_results.log}

echo "Build container ..."

docker build -t pets25-oppid .

echo "Execute container ..."
docker run --name oppid-bench --env RESULTS_FILE="/oppid/export/$RESULTS_FILE" --volume "$(pwd):/oppid/export" pets25-oppid
docker rm oppid-bench > /dev/null 2>&1

echo "Container terminated, results saved to $RESULTS_FILE"
