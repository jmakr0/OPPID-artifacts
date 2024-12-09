FROM golang:1.23-alpine

WORKDIR /oppid

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN chmod +x bin/run_benchmarks.sh

RUN mkdir -p export

ENV RESULTS_FILE="benchmark_results.log"

# Set the default command to run the benchmark script and log results
CMD ["./bin/run_benchmarks.sh", "/oppid/export/$RESULTS_FILE"]
