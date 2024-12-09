#!/bin/bash

echo "Generate circuit for metadata purposes ..."

output=$(go run bin/build_circuit.go)

echo "$output"