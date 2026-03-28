.PHONY: test-core test-file test-syslog test-webhook test-yamlconfig test-all test-integration test-bdd \
       lint-all vet-all fmt build-all bench coverage tidy check-replace check-todos check clean

MODULES := . file syslog webhook yamlconfig

# --- Per-module test targets ---

test-core:
	cd . && go test -race -v -count=1 ./...

test-file:
	cd file && go test -race -v -count=1 ./...

test-syslog:
	cd syslog && go test -race -v -count=1 ./...

test-webhook:
	cd webhook && go test -race -v -count=1 ./...

test-yamlconfig:
	cd yamlconfig && go test -race -v -count=1 ./...

test-all: test-core test-file test-syslog test-webhook test-yamlconfig

# Integration tests (requires Docker)
test-integration:
	cd file && go test -race -v -count=1 -tags=integration ./tests/integration/...
	cd syslog && go test -race -v -count=1 -tags=integration ./tests/integration/...

# BDD tests (requires Docker)
test-bdd:
	go test -race -v -count=1 -tags=integration ./tests/bdd/...

# --- Linting ---

lint-all:
	@for mod in $(MODULES); do \
		echo "=== lint $$mod ==="; \
		(cd $$mod && golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...) || exit 1; \
	done

# --- Vet ---

vet-all:
	@for mod in $(MODULES); do \
		echo "=== vet $$mod ==="; \
		(cd $$mod && go vet ./...) || exit 1; \
	done

# --- Format ---

fmt:
	gofmt -s -w .
	goimports -w .

# --- Build ---

build-all:
	@for mod in $(MODULES); do \
		echo "=== build $$mod (linux/amd64) ==="; \
		(cd $$mod && GOOS=linux GOARCH=amd64 go build ./...) || exit 1; \
		echo "=== build $$mod (darwin/arm64) ==="; \
		(cd $$mod && GOOS=darwin GOARCH=arm64 go build ./...) || exit 1; \
		echo "=== build $$mod (windows/amd64) ==="; \
		(cd $$mod && GOOS=windows GOARCH=amd64 go build ./...) || exit 1; \
	done

# --- Benchmarks ---

bench:
	go test -bench=. -benchmem -count=3 ./... | tee bench.txt

# --- Coverage ---

coverage:
	@for mod in $(MODULES); do \
		echo "=== coverage $$mod ==="; \
		(cd $$mod && go test -race -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | grep total) || exit 1; \
	done

# --- Module hygiene ---

tidy:
	@for mod in $(MODULES); do \
		echo "=== tidy $$mod ==="; \
		(cd $$mod && go mod tidy) || exit 1; \
	done

# Reject replace directives in all go.mod files
check-replace:
	@for mod in $(MODULES); do \
		if grep -q "^replace " "$$mod/go.mod" 2>/dev/null; then \
			echo "ERROR: $$mod/go.mod contains replace directive"; \
			exit 1; \
		fi; \
	done
	@echo "No replace directives found."

# Enforce TODO comments must reference a GitHub issue: TODO(#NNN)
check-todos:
	@ORPHANED=$$(grep -rn 'TODO' --include='*.go' | grep -v 'TODO(#[0-9]' | grep -v 'nolint' | grep -v '_test.go.*TODO'); \
	if [ -n "$$ORPHANED" ]; then \
		echo "ERROR: orphaned TODO without issue reference:"; \
		echo "$$ORPHANED"; \
		exit 1; \
	fi

# --- Security ---

security:
	@for mod in $(MODULES); do \
		echo "=== security $$mod ==="; \
		(cd $$mod && govulncheck ./...) || exit 1; \
	done

# --- Full local quality gate ---

check: fmt vet-all lint-all test-all tidy check-replace check-todos security
	@echo ""
	@echo "All checks passed."

# --- Clean ---

clean:
	go clean -testcache
	@for mod in $(MODULES); do \
		rm -f $$mod/coverage.out $$mod/coverage.html; \
	done
	rm -f bench.txt
