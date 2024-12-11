# Artifact Appendix

**Paper Title**: **OPPID: Single Sign-On with Oblivious Pairwise Pseudonyms**

**Artifacts HotCRP ID**: 12

**Requested Badge**: **Reproduced**

## Description
This artifact includes benchmarks of a prototype OPPID protocol implementation, as evaluated in Section 5 of the paper.

### Security/Privacy Issues and Ethical Concerns (All Badges)
The artifact poses no risks to the security or privacy of the reviewer's machine and raises no ethical concerns.

## Basic Requirements (Only for Functional and Reproduced Badges)

- **Go Programming Language**: Version 1.23 or later.
- **Docker**: For optional containerized execution.
- **Linux/macOS Environment**: Recommended.

### Hardware Requirements
The artifact does not require special hardware and can be executed on a standard laptop.

### Software Requirements
Dependencies such as `cloudflair/circle` and `gnark` are installed using `go`.

### Estimated Time and Storage Consumption
Benchmark execution is CPU-bound. On an Apple M1 (2020), it takes approximately 10 minutes.

## Environment

The artifact is accessible via GitHub and can be executed either directly or within a container.

### Accessibility (All Badges)
Artifact repository: [OPPID-artifacts](https://github.com/jmakr0/OPPID-artifacts)

### Setting up the Environment (Only for Functional and Reproduced Badges)
To prepare the environment, clone the repository and make the scripts executable:

```shell
git clone git@github.com:jmakr0/OPPID-artifacts.git
cd OPPID-artifacts
chmod +x run_benchmarks.sh
chmod +x run_benchmarks_docker.sh
```

If running locally (outside a container), install the required dependencies:
```shell
go mod download
```

### Testing the Environment (Only for Functional and Reproduced Badges)

The benchmarks can be executed using one of the following methods:

#### Direct Execution

Run the benchmarks directly:
```shell
./run_benchmarks.sh
```
Results are saved in `./benchmark_results.log` by default. Customize the output file name with:
```shell
./run_benchmarks.sh benchmark_results_custom.log
```

#### Using Docker

Run the benchmarks within a Docker container:
```shell
./run_benchmarks_docker.sh
```

Similarly, customize the log file name by passing an additional argument.

## Artifact Evaluation (Only for Functional and Reproduced Badges)

This artifact evaluates the cryptographic performance of OPPID against four other Single Sign-On (SSO) protocols, focusing on execution times and resource usage in an isolated environment.

Protocols Evaluated:
- [OIDC (OpenID Connect)](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)
- [AIF-ZKP](https://petsymposium.org/popets/2023/popets-2023-0100.php)
- [Pairwise POIDC](https://dl.acm.org/doi/10.1145/3320269.3384724)
- [UPPRESSO](https://arxiv.org/pdf/2110.10396)

Table 1 in the OPPID paper details the different security and privacy properties of these protocols in our setting.

### Main Results and Claims

The paper claims:
- OPPID is computationally efficient while meeting all security and privacy properties.

#### Main Result: Execution Times

Detailed execution times are in Table 2 (Section 5, Page 13) and available [here](https://github.com/jmakr0/OPPID/blob/main/benchmark_results_pets25.log). Key observations include:
- User operations (Init, Fin) and RP token verification (Vf): ~2ms each
- Proof verification (Res) at the IdP: 12ms after an 8ms request generation (Req) at the RP

### Experiments

The benchmark experiments contrast cryptographic operation costs across the five SSO protocols.

#### Experiment 1: Benchmarks

Execute benchmarks using:
```shell
# Direct execution
./run_benchmarks.sh

# Docker execution
./run_benchmarks_docker.sh
```
**Duration**: ~10 minutes

**Results Location**: `./benchmark_results.log`

**Output Format**:
```text
BenchmarkOPPIDInit-8                1096     1097830 ns/op           1.098 ms/op      3521 B/op       72 allocs/op
- 1096: Number of iterations
- 1097830 ns/op: Average time per operation in nanoseconds
- 1.098 ms/op: Average time per operation in milliseconds
- 3521 B/op: Bytes allocated per operation
- 72 allocs/op: Memory allocations per operation
```

**Relevant Operations**: Init, Request, Response, Finalize, Verify

**Metrics**: Execution time (ms)

**Expected Outcome**:
- *OIDC*: Res, Vf ≤ 2ms
- *AIF-ZKP*: Init, Fin ≤ 2ms; Vf ≤ 2ms; Req ≤ 7ms; Res ≤ 12ms
- *PPOIDC*: Init ≤ 4500ms; Vf ≤ 2ms; Res ≤ 6ms
- *UPPRESSO*: Init, Vf, Req ≤ 2ms; Res ≤ 2ms
- *OPPID*: Init, Fin ≤ 2ms; Vf ≤ 2ms; Req ≤ 8ms; Res ≤ 15ms

## Limitations (Only for Functional and Reproduced Badges)

All claims are expected to be reproducible under the described setup.

## Notes on Reusability (Only for Functional and Reproduced Badges)

Beyond reproducing benchmark results, the artifact allows researchers to reuse and extend the implemented building blocks. 
For example:
- Privacy-preserving RP authentication
- Implementing PS signatures, Pedersen commitments, and non-interactive zero-knowledge proofs in new SSO approaches
