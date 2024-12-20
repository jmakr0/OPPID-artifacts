# OPPID: Single Sign-On with Oblivious Pairwise Pseudonyms – Artifacts Repository

This repository contains a prototype implementation of the OPPID protocol, as described in the paper published at [PETS'25](https://petsymposium.org/2025/paperlist.php).
It also includes the evaluation benchmarks of Section 5 in the paper. Overall, these benchmarks compare the costs of the 
cryptographic operations of OPPID against four other Single Sign-On (SSO) protocols, focusing on execution times and 
resource usage in an isolated environment.

The four SSO protocols contrasted against OPPID are:
- [OIDC (OpenID Connect)](https://openid.net/specs/openid-connect-core-1_0.html)
- [AIF-ZKP](https://petsymposium.org/popets/2023/popets-2023-0100.php)
- [Pairwise POIDC](https://dl.acm.org/doi/10.1145/3320269.3384724)
- [UPPRESSO](https://arxiv.org/pdf/2110.10396)

These protocols satisfy different security and privacy properties, as detailed in Table 1 of the OPPID paper.

The cryptographic building blocks for these protocols were implemented using [cloudflare/circl](https://github.com/cloudflare/circl).
Additionally, Pairwise POIDC's pre-image proof of a standard hash function is realized through a zk-SNARK using [gnark](https://github.com/Consensys/gnark).

**Note**: The purpose of this repository is to support the evaluation of OPPID as presented in the paper. This Go module 
is not intended to be maintained. A standalone implementation of the OPPID protocol will be provided as a separate repository.

### Repository Structure

```text
OPPID-artifacts/
├── benchmark/                 # Benchmarks for OPPID and the four other SSO protocols
├── pkg/                       # Go packages implementing cryptographic building blocks
├── protocol/                  # Protocol definitions and implementations
├── dockerfile                 # Docker configuration for containerized benchmarking
├── run_benchmarks.sh           # Execute benchmarks directly (requires dependency setup)
├── run_benchmarks_docker.sh    # Execute benchmarks within a docker container
```

## Setup

Before running the benchmarks, ensure that the environment is properly set up.

#### Prerequisites
- **Go programming language**: Version 1.23 or later.
- **Docker**: For containerized execution (optional).
- **Linux/macOS environment** (recommended).

#### Installation

Make scripts executable:
```shell
chmod +x run_benchmarks.sh
chmod +x run_benchmarks_docker.sh
```

If running benchmarks locally (outside a container), install the required dependencies:
```shell
go mod download
```

## Benchmark Execution

Benchmarks can be executed using either of the following methods:

#### Direct Execution

To execute the benchmarks directly, run:
```shell
./run_benchmarks.sh
```

Results will be stored in `./benchmark_results.log` by default. You can also customize the output file name using:
```shell
./run_benchmarks.sh benchmark_results_custom.log
```

#### Using Docker

To execute all benchmarks within a Docker container, run:
```shell
./run_benchmarks_docker.sh
```

As with direct execution, you can customize the log file name using an additional argument.

### Interpreting Benchmark Results

Benchmark results are saved in a format that includes details about execution time and memory usage for each protocol.
An example result entry:
```text
BenchmarkOPPIDInit-8                1096     1097830 ns/op           1.098 ms/op      3521 B/op       72 allocs/op
- 1096: Number of iterations
- 1097830 ns/op: Average time per operation in nanoseconds
- 1.098 ms/op: Average time per operation in milliseconds
- 3521 B/op: Bytes allocated per operation
- 72 allocs/op: Memory allocations per operation
```

### Evaluation Results

The benchmarks for the PETS'25 paper were conducted on an Apple M1 CPU (8-core, 2020, 3.2 GHz).
You can find the results in [benchmark_results_pets25.log](benchmark_results_pets25.log).

## Additional Tests & Benchmarks

All packages include test cases and benchmarks that can be executed directly.

To execute all package tests:
```shell
go test -timeout=60m ./pkg/...
```
Note that this might take a while (~15-20min) because of the large proof generation required by the `ppoidc` protocol.

To benchmark (but not the tests) all packages:
```shell
go test -run=none -bench=. -timeout=120m -benchmem ./pkg/...
```

### Circuit Details

To obtain information about the compiled (R1CS) circuit, which is required for Pairwise PPOIDC, execute the following:
```shell
go test -v -run ^TestCircuitMetadata$ ./pkg/other/nizk/hash
```
The test outputs key metrics for your reference, including:
- Number of constraints: The total constraints in the circuit
- Key generation time: The time required for key generation (measured in seconds)
- Size of the circuit (in MB)
- Size of the proving key (in MB)
- Size of the verification key (in MB)

## Citing

If you use this implementation in your research or draw insights from the OPPID paper, please consider citing it.
```bib
@inproceedings{PETS:KroLehOez25,
    author    = {Maximilian Kroschewski and Anja Lehmann and Cavit Özbay},
    title     = {OPPID: Single Sign-On with Oblivious Pairwise Pseudonyms},
    journal   = {Proceedings on Privacy Enhancing Technologies},
    year      = {2025}
}
```
