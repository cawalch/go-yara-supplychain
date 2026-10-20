# Stage 1: Build static binary
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /bin/go-yara-supplychain \
    ./cmd/go-yara-supplychain

# Stage 2: Minimal static non-root runtime container (suitable for Vela CI/CD and CLI)
FROM gcr.io/distroless/static-debian12:nonroot

LABEL maintainer="cawalch"
LABEL description="go-yara-supplychain: pure-Go supply chain malware detection engine (Vela CI/CD plugin compatible)"

COPY --from=builder /bin/go-yara-supplychain /bin/go-yara-supplychain

ENTRYPOINT ["/bin/go-yara-supplychain"]
