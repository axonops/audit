# Build stage — compiles from the repo root so all local modules are available.
FROM golang:1.26-alpine AS builder
WORKDIR /src

# Copy all module files for dependency resolution.
COPY go.mod go.sum ./
COPY file/go.mod file/go.sum ./file/
COPY syslog/go.mod syslog/go.sum ./syslog/
COPY webhook/go.mod webhook/go.sum ./webhook/
COPY loki/go.mod loki/go.sum ./loki/
COPY outputconfig/go.mod outputconfig/go.sum ./outputconfig/
COPY outputs/go.mod outputs/go.sum ./outputs/
COPY secrets/go.mod secrets/go.sum ./secrets/
COPY secrets/openbao/go.mod secrets/openbao/go.sum ./secrets/openbao/
COPY secrets/vault/go.mod secrets/vault/go.sum ./secrets/vault/
COPY cmd/audit-gen/go.mod cmd/audit-gen/go.sum ./cmd/audit-gen/
COPY examples/17-capstone/go.mod examples/17-capstone/go.sum ./examples/17-capstone/

# Create workspace for local module resolution.
RUN go work init . file syslog webhook loki outputconfig outputs \
    cmd/audit-gen secrets secrets/openbao secrets/vault examples/17-capstone
RUN go mod download

# Copy source.
COPY . .
RUN cd examples/17-capstone && CGO_ENABLED=0 go build -o /app .

# Runtime stage — minimal image with just the binary and runtime config.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
WORKDIR /app
COPY --from=builder /app /app/server
COPY examples/17-capstone/outputs.yaml /app/outputs.yaml
RUN mkdir -p /data
EXPOSE 8080

ENV AUDIT_CONFIG_PATH=/app/outputs.yaml \
    LISTEN_ADDR=:8080 \
    DATABASE_URL=postgres://demo:demo@postgres:5432/audit_demo?sslmode=disable \
    LOKI_URL=http://loki:3100/loki/api/v1/push \
    AUDIT_LOG_PATH=/data/audit.log \
    SECURITY_LOG_PATH=/data/security.log

ENTRYPOINT ["/app/server"]
