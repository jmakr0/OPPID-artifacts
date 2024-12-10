FROM golang:1.23-alpine

WORKDIR /oppid

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN chmod +x run_benchmarks.sh

RUN mkdir -p export

ENV RESULTS_FILE="benchmark_results.log"

CMD ["sh", "-c", "./run_benchmarks.sh $RESULTS_FILE"]
