# Artifact Appendix

Paper title: **OPPID: Single Sign-On with Oblivious Pairwise Pseudonyms**

Artifacts HotCRP Id: **todo** (enter artifacts id)

Requested Badge: **Reproduced**

## Description
Artifact provides OPPID protocol implementation and benchmarks, evaluated in Section 5 of the paper.

### Security/Privacy Issues and Ethical Concerns (All badges)
The artifact does not hold any risks to the security or privacy of the reviewer's machine as well as ethical concerns.

## Basic Requirements (Only for Functional and Reproduced badges)
- **Go programming language**: Version 1.23 or later.
- **Docker**: For containerized execution (optional).
- **Linux/macOS environment** (recommended).

### Hardware Requirements
The artifact does not require special hardware.

### Software Requirements
No third-party software, data sets, or models are required.

### Estimated Time and Storage Consumption
Operations are mostly CPU bound. Benchmark execution in an Apple M1 (2020) requires about XXX minutes.

## Environment
Access is given via GitHub and execution can be done either directly or through a container.

### Accessibility (All badges)
The artifact can be reviewed under: [OPPID](https://github.com/jmakr0/OPPID)

### Set up the environment (Only for Functional and Reproduced badges)
Clone repository and make all executables runnable:
```bash
git clone git@github.com:jmakr0/OPPID.git
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
./bin/run_benchmarks.sh
```

Results will be stored in `./benchmark_results.log` by default. You can also customize the output file name using:
```shell
./bin/run_benchmarks.sh benchmark_results_custom.log
```

#### Using Docker

To execute all benchmarks within a Docker container, run:
```shell
./bin/run_benchmarks_container.sh
```
As with direct execution, you can customize the log file name using an additional argument.


## Artifact Evaluation (Only for Functional and Reproduced badges)
This section includes all the steps required to evaluate your artifact's functionality and validate your paper's key results and claims.
Therefore, highlight your paper's main results and claims in the first subsection. And describe the experiments that support your claims in the subsection after that.

### Main Results and Claims
List all your paper's results and claims that are supported by your submitted artifacts.

#### Main Result 1: Name
Describe the results in 1 to 3 sentences.
Refer to the related sections in your paper and reference the experiments that support this result/claim.

#### Main Result 2: Name
...

### Experiments
List each experiment the reviewer has to execute. Describe:
- How to execute it in detailed steps.
- What the expected result is.
- How long it takes and how much space it consumes on disk. (approximately)
- Which claim and results does it support, and how.

#### Experiment 1: Name
Provide a short explanation of the experiment and expected results.
Describe thoroughly the steps to perform the experiment and to collect and organize the results as expected from your paper.
Use code segments to support the reviewers, e.g.,
```bash
python experiment_1.py
```
#### Experiment 2: Name
...

#### Experiment 3: Name
...

## Limitations (Only for Functional and Reproduced badges)
Describe which tables and results are included or are not reproducible with the provided artifact.
Provide an argument why this is not included/possible.

## Notes on Reusability (Only for Functional and Reproduced badges)
First, this section might not apply to your artifacts.
Use it to share information on how your artifact can be used beyond your research paper, e.g., as a general framework.
The overall goal of artifact evaluation is not only to reproduce and verify your research but also to help other researchers to re-use and improve on your artifacts.
Please describe how your artifacts can be adapted to other settings, e.g., more input dimensions, other datasets, and other behavior, through replacing individual modules and functionality or running more iterations of a specific part.