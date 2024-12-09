FROM golang:1.23-alpine

WORKDIR /oppid

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN chmod +x bin/run_benchmarks.sh

CMD ["./bin/run_benchmarks.sh"]
