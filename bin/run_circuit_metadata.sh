#!/bin/bash

echo "Generate circuit ..."

cd pkg/nizk/hash

# Run the build test and capture the output
output=$(go test -v build_test.go | grep -E "^=== RUN|^--- PASS|^--- FAIL|^[^\s].*")

echo "$output"