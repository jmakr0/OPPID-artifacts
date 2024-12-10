# Artifact Appendix

Paper title: **OPPID: Single Sign-On with Oblivious Pairwise Pseudonyms**

Artifacts HotCRP Id: 12

Requested Badge: **Reproduced**

## Description
This artifact provides benchmarks of a prototypical OPPID protocol implementation, evaluated in Section 5 of the paper.

### Security/Privacy Issues and Ethical Concerns (All badges)
The artifact does not hold any risks to the security or privacy of the reviewer's machine as well as ethical concerns.

## Basic Requirements (Only for Functional and Reproduced badges)
- **Go programming language**: Version 1.23 or later.
- **Docker**: For containerized execution (optional).
- **Linux/macOS environment** (recommended).

### Hardware Requirements
The artifact does not require special hardware (can be executed on a laptop).

### Software Requirements
All packages (cloudflair/circle, gnark) will be setup with `go`.

### Estimated Time and Storage Consumption
Operations are mostly CPU bound. Benchmark execution on an Apple M1 (2020) requires about 10 minutes.


## Environment
Access is given via GitHub and execution can be done either directly or through a container.

### Accessibility (All badges)
The artifact can be reviewed under: [OPPID-artifacts](https://github.com/jmakr0/OPPID-artifacts)

### Set up the environment (Only for Functional and Reproduced badges)
Clone repository and make all executables runnable:
```bash
git clone git@github.com:jmakr0/OPPID-artifacts.git
chmod +x bin/*.sh
```

If running benchmarks locally (outside a container), install the required dependencies:
```shell
go mod download
```

### Testing the Environment (Only for Functional and Reproduced badges)

The artifact can be executed using either of the following methods:

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


## Artifact Evaluation (Only for Functional and Reproduced badges)

The benchmarks compare the costs of the cryptographic operations of OPPID against four other Single Sign-On (SSO) protocols, 
focusing on execution times and resource usage in an isolated environment.

The four SSO protocols contrasted against OPPID are:
- [OIDC (OpenID Connect)](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)
- [AIF-ZKP](https://petsymposium.org/popets/2023/popets-2023-0100.php)
- [Pairwise POIDC](https://dl.acm.org/doi/10.1145/3320269.3384724)
- [UPPRESSO](https://arxiv.org/pdf/2110.10396)

These protocols satisfy different security and privacy properties, as detailed in Table 1 of the OPPID paper.

### Main Results and Claims

The evaluation claims that:
- OPPID performs reasonable efficient, given that it satisfies all security/privacy properties
- Its communication costs (request sizes sent to the IdP) are relatively small 

#### Main Result 1: Execution Times

The execution times are shown in Table 2 in Section 5 on page 13 and can also be found [here](https://github.com/jmakr0/OPPID/blob/main/benchmark_results_pets25.log). 
The results are summarizes in the paragraph *Evaluation Results*.
For OPPID, user operations (Init, Fin) and token verification (Vf)
each take only about 2ms, proof verification (Res) at the IdP requires only 12ms
after a 8ms generation time at the RP (Req).

#### Main Result 2: Communication Costs

todo: its more an "observation" than a main result; put it as "sub-case" of the previous

The communications costs are:
- OPPID: the authentication proof and blinded `rid` value result in 864 bytes
- PPOIDC: the pre-compiled circuit has 56MB and a 121MB proving key

### Experiments

List each experiment the reviewer has to execute. Describe:
- How to execute it in detailed steps.
- What the expected result is.
- How long it takes and how much space it consumes on disk. (approximately)
- Which claim and results does it support, and how.

#### Experiment 1: Benchmarks
The benchmarks can be executed as follows:
```shell
# Either directly
./run_benchmarks.sh

# Or using docker
./run_benchmarks_docker.sh
```
Results will be stored in `./benchmark_results.log` and exhibit a format that includes details about execution 
time and memory usage for each protocol. An example result entry:
```text
BenchmarkOPPIDInit-8                1096     1097830 ns/op           1.098 ms/op      3521 B/op       72 allocs/op
- 1096: Number of iterations
- 1097830 ns/op: Average time per operation in nanoseconds
- 1.098 ms/op: Average time per operation in milliseconds
- 3521 B/op: Bytes allocated per operation
- 72 allocs/op: Memory allocations per operation
```
**Relevant Operations:** Init, Request, Response, Finalize, Verify
**Relevant Metrics:** Execution time in ms

#### Experiment 2: Communication Costs
The costs for an Element in $(Z_q, G_1, G_2, G_T)$ are 
([32](https://github.com/cloudflare/circl/blob/91946a37b9b8da646abe6252153d918707cda136/ecc/bls12381/ff/scalar.go#L10), [48](https://github.com/cloudflare/circl/blob/91946a37b9b8da646abe6252153d918707cda136/ecc/bls12381/g1.go#L18), [92](https://github.com/cloudflare/circl/blob/91946a37b9b8da646abe6252153d918707cda136/ecc/bls12381/g2.go#L16), [576](https://github.com/cloudflare/circl/blob/91946a37b9b8da646abe6252153d918707cda136/ecc/bls12381/gt.go#L6),)
byes.

- OPPID: The proof struct can be seen [here](), encompassing $(3Z_q + 3G_1 + 1G_T)$ plus the blinded `rid` value with $1G_1$, resulting in $ 3*32+4*48+576=864 $ bytes.

To obtain detailed information about the compiled (R1CS) circuit, which is required for PPOIDC, execute the following script:
```shell
go test -v -run ^TestCircuitMetadata$ ./pkg/other/nizk/hash
```
This script outputs key metrics for your reference, including:
- Number of constraints: The total constraints in the circuit
- Key generation time: The time required for key generation (measured in seconds)
- Size of the circuit (in MB)
- Size of the proving key (in MB)
- Size of the verification key (in MB)

## Limitations (Only for Functional and Reproduced badges)
All claims should be reproducible.

## Notes on Reusability (Only for Functional and Reproduced badges)

todo

First, this section might not apply to your artifacts.
Use it to share information on how your artifact can be used beyond your research paper, e.g., as a general framework.
The overall goal of artifact evaluation is not only to reproduce and verify your research but also to help other researchers to re-use and improve on your artifacts.
Please describe how your artifacts can be adapted to other settings, e.g., more input dimensions, other datasets, and other behavior, through replacing individual modules and functionality or running more iterations of a specific part.