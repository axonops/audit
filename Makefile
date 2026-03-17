.PHONY: test test-race test-integration test-bdd lint vet fmt build check bench coverage clean

# Unit tests
test:
	go test -v -count=1 ./...

# Unit tests with race detector
test-race:
	go test -race -v -count=1 ./...

# Integration tests (requires Docker)
test-integration:
	go test -race -v -count=1 -tags=integration ./tests/integration/...

# BDD tests (requires Docker)
test-bdd:
	go test -race -v -count=1 -tags=integration ./tests/bdd/...

# Lint
lint:
	golangci-lint run --timeout=5m ./...

# Vet
vet:
	go vet ./...

# Format
fmt:
	gofmt -s -w .
	goimports -w .

# Build
build:
	go build ./...

# Cross-platform build verification
build-all:
	GOOS=linux   GOARCH=amd64 go build ./...
	GOOS=darwin  GOARCH=arm64 go build ./...
	GOOS=windows GOARCH=amd64 go build ./...

# Benchmarks
bench:
	go test -bench=. -benchmem -count=3 ./... | tee bench.txt

# Coverage report
coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | grep total
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Module hygiene
tidy:
	go mod tidy
	@git diff --exit-code go.mod go.sum || (echo "ERROR: go.mod/go.sum not tidy" && exit 1)

# Security checks
security:
	govulncheck ./...
	gosec -quiet ./...

# Full local quality gate — run before marking anything done
check: fmt vet lint test-race tidy
	@echo ""
	@echo "All checks passed."

# Clean test cache
clean:
	go clean -testcache
	rm -f coverage.out coverage.html bench.txt
