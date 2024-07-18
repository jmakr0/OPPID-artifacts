# OPPID: Single Sign-On with Oblivious Pairwise Pseudonyms

tbd.

### Getting Started

#### Prerequisites

- Go 1.22.4 or later

#### Installation

1.	Clone the repository:
```console
      git clone https://github.com/jmakr0/OPPID.git
      cd OPPID
```
2. Download the dependencies:
```console
go mod tidy
```

### Running the Protocols

Each protocol is implemented in the protocol directory and can be benchmarked using the provided benchmark tests.

#### Benchmarking

To run benchmarks for all protocols:

1. Make the benchmark script executable:
```console
chmod +x script/run_benchmarks.sh
```
2. Run the benchmark script:
```console
./script/run_benchmarks.sh
```
This will execute the benchmarks and save the results to benchmark_results.txt.

#### Interpreting Benchmark Results

The benchmark results will be saved in a format that includes information about the time taken and memory used for each protocol. An example entry in benchmark_results.txt might look like:
```
BenchmarkOPPIDInit-8          	    1096	   1097830 ns/op	         1.098 ms/op	    3521 B/op	      72 allocs/op
```
- 1096 is the number of iterations.
- 1097830 ns/op is the average time per operation in nanoseconds.
- 1.098 ms/op is the average time per operation in milliseconds.
- 3521 B/op is the number of bytes allocated per operation. 
- 72 allocs/op is the number of memory allocations per operation.
