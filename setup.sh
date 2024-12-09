#!/bin/sh

echo "Start setup ..."

echo "Make required scripts executable"
chmod +x run_container_benchmarks.sh
chmod +x bin/*.sh

echo "Install dependencies"
go mod download

echo "Setup completed"
