#!/bin/sh

RESULTS_FILE=${1:-benchmark_results.log}

echo "Build container ..."

docker build -t pets25-oppid-img .

echo "Execute container ..."
docker run --name oppid-bench --env RESULTS_FILE="/oppid/export/$RESULTS_FILE" --volume "$(pwd):/oppid/export" pets25-oppid-img
docker rm oppid-bench > /dev/null 2>&1

echo "Container terminated, results locally saved to $RESULTS_FILE"
