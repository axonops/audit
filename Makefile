.PHONY: test test-all test-core test-file test-syslog test-webhook test-outputconfig test-audit-gen \
       test-integration test-bdd test-examples \
       lint lint-all lint-core lint-file lint-syslog lint-webhook lint-outputconfig lint-audit-gen lint-crud-api \
       vet vet-all fmt fmt-check \
       build build-all bench bench-save bench-compare coverage \
       tidy tidy-check verify check-replace check-todos \
       security release-check check clean \
       install-tools install-benchstat workspace generate-certs \
       test-infra-up test-infra-down test-infra-logs

# --- Configuration ---

MODULES           := . file syslog webhook outputconfig cmd/audit-gen
WORKSPACE_MODULES := $(MODULES) examples/09-crud-api
GOBIN             := $(shell go env GOPATH)/bin
GO_TOOLCHAIN      := go1.26.1

# Tool versions — pinned for supply chain safety. To update:
#   1. Change the version constant below
#   2. Run: make install-tools
#   3. Verify: make check
#   4. Commit the Makefile change (CI cache auto-invalidates via hashFiles)
GOLANGCI_LINT_VER := v2.1.6
GOVULNCHECK_VER   := v1.1.4
GOIMPORTS_VER     := v0.43.0
GORELEASER_VER    := v2.15.0
BENCHSTAT_VER     := v0.0.0-20260312031701-16a31bc5fbd0

# --- Tool management ---

install-tools:
	@echo "Installing tools with GOTOOLCHAIN=$(GO_TOOLCHAIN)..."
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VER)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VER)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VER)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/goreleaser/goreleaser/v2@$(GORELEASER_VER)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/perf/cmd/benchstat@$(BENCHSTAT_VER)
	@echo "Tools installed to $(GOBIN)"

install-benchstat:
	@echo "Installing benchstat with GOTOOLCHAIN=$(GO_TOOLCHAIN)..."
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/perf/cmd/benchstat@$(BENCHSTAT_VER)
	@echo "benchstat installed to $(GOBIN)"

# --- Workspace ---

workspace:
	@rm -f go.work go.work.sum
	go work init $(WORKSPACE_MODULES)

# --- Per-module test targets ---

test-core:
	cd . && go test -race -v -count=1 -coverprofile=coverage.out $$(go list ./... | grep -v /tests/ | grep -v /internal/testhelper | grep -v /examples/)

test-file:
	cd file && go test -race -v -count=1 -coverprofile=coverage.out ./...

test-syslog:
	cd syslog && go test -race -v -count=1 -coverprofile=coverage.out ./...

test-webhook:
	cd webhook && go test -race -v -count=1 -coverprofile=coverage.out ./...

test-outputconfig:
	cd outputconfig && go test -race -v -count=1 -coverprofile=coverage.out $$(go list ./... | grep -v /tests/)

test-audit-gen:
	cd cmd/audit-gen && go test -race -v -count=1 -coverprofile=coverage.out ./...

test-all: test-core test-file test-syslog test-webhook test-outputconfig test-audit-gen
test: test-all

# Integration tests (requires Docker: make test-infra-up first)
test-integration:
	cd file && go test -race -v -count=1 -tags=integration ./tests/integration/...
	cd syslog && go test -race -v -count=1 -tags=integration ./tests/integration/...
	cd webhook && go test -race -v -count=1 -tags=integration ./tests/integration/...
	go test -race -v -count=1 -tags=integration ./tests/integration/...

# BDD tests (requires Docker for syslog/webhook scenarios)
test-bdd:
	go test -race -v -count=1 -tags=integration ./tests/bdd/...
	cd outputconfig && go test -race -v -count=1 ./tests/bdd/...

# Example compilation tests (no runtime — examples are documentation)
test-examples:
	@for dir in examples/01-basic examples/03-file-output examples/04-multi-output \
	            examples/02-code-generation examples/05-event-routing \
	            examples/06-sensitivity-labels examples/07-formatters \
	            examples/08-middleware examples/09-crud-api \
	            examples/10-testing; do \
		echo "=== build $$dir ==="; \
		(cd $$dir && go build -o /dev/null .) || exit 1; \
	done

# --- Linting ---

lint-core:
	cd . && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-file:
	cd file && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-syslog:
	cd syslog && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-webhook:
	cd webhook && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-outputconfig:
	cd outputconfig && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-audit-gen:
	cd cmd/audit-gen && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-crud-api:
	cd examples/09-crud-api && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-all: lint-core lint-file lint-syslog lint-webhook lint-outputconfig lint-audit-gen lint-crud-api
lint: lint-all

# --- Vet ---

vet-all:
	@for mod in $(MODULES); do \
		echo "=== vet $$mod ==="; \
		(cd $$mod && go vet ./...) || exit 1; \
	done
vet: vet-all

# --- Format ---

# gofmt ships with the Go toolchain — not installed to GOBIN.
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
	@rm -f bench.txt
	@for mod in $(MODULES); do \
		echo "=== bench $$mod ===" | tee -a bench.txt; \
		(cd $$mod && go test -bench=. -benchmem -count=5 -run='^$$' ./... | tee -a $(CURDIR)/bench.txt) || exit 1; \
	done

bench-save: bench
	cp bench.txt bench-baseline.txt
	@echo "Baseline saved to bench-baseline.txt"

bench-compare: bench
	@if [ -f bench-baseline.txt ]; then \
		$(GOBIN)/benchstat bench-baseline.txt bench.txt; \
	else \
		echo "No bench-baseline.txt found. Run 'make bench-save' first."; \
		exit 1; \
	fi

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
		 ([ ! -f go.sum.bak ] || diff -q go.sum go.sum.bak > /dev/null 2>&1) && \
		 rm -f go.mod.bak go.sum.bak || \
		 { echo "ERROR: go mod tidy produced changes in $$mod"; \
		   mv go.mod.bak go.mod 2>/dev/null; mv go.sum.bak go.sum 2>/dev/null; exit 1; }) || exit 1; \
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

check: fmt-check vet-all lint-all test-all build-all test-examples tidy-check verify check-replace check-todos release-check security
	@echo ""
	@echo "All checks passed."

# --- Clean ---

clean:
	go clean -testcache
	@for mod in $(MODULES); do \
		rm -f $$mod/coverage.out $$mod/coverage.html; \
	done
	rm -f bench.txt

# --- Certificate generation ---

generate-certs:
	scripts/generate-test-certs.sh

# --- Test infrastructure (Docker) ---

COMPOSE_DIR := tests/bdd

test-infra-up:
	docker network create audit-test 2>/dev/null || true
	docker compose -f $(COMPOSE_DIR)/docker-compose.full.yml up -d --build --wait
	@echo "Test infrastructure is ready."

test-infra-down:
	docker compose -f $(COMPOSE_DIR)/docker-compose.full.yml down -v
	docker network rm audit-test 2>/dev/null || true

test-infra-logs:
	docker compose -f $(COMPOSE_DIR)/docker-compose.full.yml logs
