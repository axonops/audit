.PHONY: test test-all test-core test-file test-syslog test-webhook test-yamlconfig \
       test-integration test-bdd \
       lint lint-all lint-core lint-file lint-syslog lint-webhook lint-yamlconfig \
       vet vet-all fmt fmt-check \
       build build-all bench coverage \
       tidy tidy-check verify check-replace check-todos \
       security release-check check clean \
       install-tools workspace

# --- Configuration ---

MODULES           := . file syslog webhook yamlconfig
GOBIN             := $(shell go env GOPATH)/bin
GO_TOOLCHAIN      := go1.26.1
GOLANGCI_LINT_VER := v2.1.6

# --- Tool management ---

install-tools:
	@echo "Installing tools with GOTOOLCHAIN=$(GO_TOOLCHAIN)..."
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VER)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/vuln/cmd/govulncheck@latest
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/tools/cmd/goimports@latest
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/goreleaser/goreleaser/v2@latest
	@echo "Tools installed to $(GOBIN)"

# --- Workspace ---

workspace:
	go work init $(MODULES)

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
test: test-all

# Integration tests (requires Docker)
test-integration:
	cd file && go test -race -v -count=1 -tags=integration ./tests/integration/...
	cd syslog && go test -race -v -count=1 -tags=integration ./tests/integration/...

# BDD tests (requires Docker)
test-bdd:
	go test -race -v -count=1 -tags=integration ./tests/bdd/...

# --- Linting ---

lint-core:
	cd . && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-file:
	cd file && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-syslog:
	cd syslog && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-webhook:
	cd webhook && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-yamlconfig:
	cd yamlconfig && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-all: lint-core lint-file lint-syslog lint-webhook lint-yamlconfig
lint: lint-all

# --- Vet ---

vet-all:
	@for mod in $(MODULES); do \
		echo "=== vet $$mod ==="; \
		(cd $$mod && go vet ./...) || exit 1; \
	done
vet: vet-all

# --- Format ---

fmt:
	gofmt -s -w .
	$(GOBIN)/goimports -w .

fmt-check:
	@echo "=== gofmt ==="
	@DIFF=$$(gofmt -s -l .); if [ -n "$$DIFF" ]; then echo "Files need gofmt -s:"; echo "$$DIFF"; exit 1; fi
	@echo "=== goimports ==="
	@DIFF=$$($(GOBIN)/goimports -l .); if [ -n "$$DIFF" ]; then echo "Files need goimports:"; echo "$$DIFF"; exit 1; fi

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
build: build-all

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

tidy-check:
	@for mod in $(MODULES); do \
		echo "=== tidy-check $$mod ==="; \
		(cd $$mod && \
		 cp go.mod go.mod.bak && (cp go.sum go.sum.bak 2>/dev/null; true) && \
		 go mod tidy && \
		 diff -q go.mod go.mod.bak > /dev/null 2>&1 && \
		 ([ ! -f go.sum.bak ] || diff -q go.sum go.sum.bak > /dev/null 2>&1) || \
		 (echo "ERROR: go mod tidy produced changes in $$mod"; \
		  mv go.mod.bak go.mod; (mv go.sum.bak go.sum 2>/dev/null; true); exit 1); \
		 rm -f go.mod.bak go.sum.bak) || exit 1; \
	done

verify:
	@for mod in $(MODULES); do \
		echo "=== verify $$mod ==="; \
		(cd $$mod && go mod verify) || exit 1; \
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
		(cd $$mod && $(GOBIN)/govulncheck ./...) || exit 1; \
	done

# --- Release ---

release-check:
	$(GOBIN)/goreleaser check

# --- Full local quality gate ---

check: fmt-check vet-all lint-all test-all tidy-check verify check-replace check-todos release-check security
	@echo ""
	@echo "All checks passed."

# --- Clean ---

clean:
	go clean -testcache
	@for mod in $(MODULES); do \
		rm -f $$mod/coverage.out $$mod/coverage.html; \
	done
	rm -f bench.txt
