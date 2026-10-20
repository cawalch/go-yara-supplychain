.PHONY: all build test test-race lint check fmt clean train

all: check build

train:
	go run ./tools/train

build:
	go build -v -o bin/go-yara-supplychain ./cmd/go-yara-supplychain

test:
	go test -v ./...

test-race:
	go test -race -v ./...

lint:
	golangci-lint run --config=.golangci.yml
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

check: fmt-check lint test-race

fmt:
	goimports -w .
	gofmt -s -w .

fmt-check:
	@diff=$$(gofmt -s -d .); \
	if [ -n "$$diff" ]; then \
		echo "The following files need gofmt:"; \
		echo "$$diff"; \
		exit 1; \
	fi

clean:
	rm -rf bin/
