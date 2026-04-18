.PHONY: test test-all test-core test-file test-syslog test-webhook test-loki test-outputconfig test-audit-gen \
       test-secrets test-secrets-openbao test-secrets-vault \
       test-integration test-bdd test-bdd-core test-bdd-outputconfig test-bdd-file test-bdd-syslog test-bdd-webhook test-bdd-loki test-bdd-fanout \
       test-bdd-verify \
       test-examples \
       lint lint-all lint-core lint-file lint-syslog lint-webhook lint-loki lint-outputconfig lint-audit-gen lint-capstone \
       lint-secrets lint-secrets-openbao lint-secrets-vault \
       vet vet-all fmt fmt-check \
       build build-all bench bench-save bench-compare coverage \
       tidy tidy-check verify check-replace check-todos check-bdd-strict \
       security release-check check clean \
       install-tools install-benchstat workspace generate-certs \
       test-infra-up test-infra-down test-infra-logs \
       test-infra-syslog-up test-infra-syslog-down \
       test-infra-webhook-up test-infra-webhook-down \
       test-infra-loki-up test-infra-loki-down \
       test-infra-openbao-up test-infra-openbao-down \
       test-infra-vault-up test-infra-vault-down \
       test-bdd-secrets \
       sbom sbom-validate

# --- Configuration ---

# Force bash with pipefail so recipe pipelines don't silently mask failures.
# Without this, `cmd | tee file` exits 0 even when `cmd` fails — the same
# bug class that hid BDD failures in CI before #622. Recipes that rely on
# `grep`'s non-zero-on-no-match (e.g. check-todos) must use `|| true`.
SHELL      := bash
.SHELLFLAGS := -e -o pipefail -c

MODULES           := . file syslog webhook loki outputconfig outputs cmd/audit-gen secrets secrets/openbao secrets/vault
WORKSPACE_MODULES := $(MODULES) examples/17-capstone
GOBIN             := $(shell go env GOPATH)/bin
GO_TOOLCHAIN      := go1.26.2

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

test-loki:
	cd loki && go test -race -v -count=1 -coverprofile=coverage.out ./...

test-outputconfig:
	cd outputconfig && go test -race -v -count=1 -coverprofile=coverage.out $$(go list ./... | grep -v /tests/)

test-audit-gen:
	cd cmd/audit-gen && go test -race -v -count=1 -coverprofile=coverage.out ./...

test-secrets:
	cd secrets && go test -race -v -count=1 -coverprofile=coverage.out ./...

test-secrets-openbao:
	cd secrets/openbao && go test -race -v -count=1 -coverprofile=coverage.out ./...

test-secrets-vault:
	cd secrets/vault && go test -race -v -count=1 -coverprofile=coverage.out ./...

test-all: test-core test-file test-syslog test-webhook test-loki test-outputconfig test-audit-gen test-secrets test-secrets-openbao test-secrets-vault
test: test-all

# Integration tests (requires Docker: make test-infra-up first)
test-integration:
	cd file && go test -race -v -count=1 -tags=integration ./tests/integration/...
	cd syslog && go test -race -v -count=1 -tags=integration ./tests/integration/...
	cd webhook && go test -race -v -count=1 -tags=integration ./tests/integration/...
	cd loki && go test -race -v -count=1 -tags=integration ./tests/integration/...
	go test -race -v -count=1 -tags=integration ./tests/integration/...
	cd secrets/openbao && go test -race -v -count=1 -tags=integration ./tests/integration/...
	cd secrets/vault && go test -race -v -count=1 -tags=integration ./tests/integration/...

# BDD tests — all scenarios (requires Docker for syslog/webhook/loki scenarios)
test-bdd:
	go test -race -v -count=1 -tags=integration ./tests/bdd/...
	cd outputconfig && go test -race -v -count=1 ./tests/bdd/...

# BDD tests — per-tag runners for parallel CI execution.
# Core and file need no Docker. Others require specific infrastructure.
test-bdd-core:
	BDD_TAGS="@core && ~@docker" go test -race -v -count=1 -tags=integration ./tests/bdd/...

test-bdd-outputconfig:
	cd outputconfig && go test -race -v -count=1 ./tests/bdd/...

test-bdd-file:
	BDD_TAGS=@file go test -race -v -count=1 -tags=integration ./tests/bdd/...

test-bdd-syslog:
	BDD_TAGS=@syslog go test -race -v -count=1 -tags=integration ./tests/bdd/...

test-bdd-webhook:
	BDD_TAGS="@webhook, @routing" go test -race -v -count=1 -tags=integration ./tests/bdd/...

test-bdd-loki:
	BDD_TAGS="@loki && ~@fanout" go test -race -v -count=1 -tags=integration ./tests/bdd/...

test-bdd-fanout:
	BDD_TAGS=@fanout go test -race -v -count=1 -tags=integration ./tests/bdd/...

test-bdd-secrets:
	cd outputconfig && go test -race -v -count=1 -tags=integration -run TestOutputConfigDockerFeatures ./tests/bdd/...

# BDD coverage verification — ensure every scenario is covered by at least one runner.
# This is a static check that evaluates tag expressions against feature files.
# Runs in CI after all BDD matrix entries complete, and locally before release.
test-bdd-verify:
	./scripts/verify-bdd-coverage.sh

# Example compilation tests (no runtime — examples are documentation)
test-examples:
	@for dir in examples/01-basic examples/02-code-generation \
	            examples/03-file-output examples/04-testing \
	            examples/05-formatters examples/06-middleware \
	            examples/07-syslog-output examples/08-webhook-output \
	            examples/09-multi-output examples/10-event-routing \
	            examples/11-sensitivity-labels examples/12-hmac-integrity \
	            examples/13-standard-fields examples/14-loki-output \
	            examples/15-tls-policy examples/16-buffering \
	            examples/17-capstone; do \
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

lint-loki:
	cd loki && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-outputconfig:
	cd outputconfig && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-audit-gen:
	cd cmd/audit-gen && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-secrets:
	cd secrets && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-secrets-openbao:
	cd secrets/openbao && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-secrets-vault:
	cd secrets/vault && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-capstone:
	cd examples/17-capstone && $(GOBIN)/golangci-lint run --timeout=5m --config $(CURDIR)/.golangci.yml ./...

lint-all: lint-core lint-file lint-syslog lint-webhook lint-loki lint-outputconfig lint-audit-gen lint-secrets lint-secrets-openbao lint-secrets-vault lint-capstone
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
	@ORPHANED=$$({ grep -rn 'TODO' --include='*.go' || true; } | { grep -v 'TODO(#[0-9]' || true; } | { grep -v 'nolint' || true; } | { grep -v '_test.go.*TODO' || true; }); \
	if [ -n "$$ORPHANED" ]; then \
		echo "ERROR: orphaned TODO without issue reference:"; \
		echo "$$ORPHANED"; \
		exit 1; \
	fi

# Enforce godog runners use Strict mode so undefined steps fail the
# suite. This is the contract established by #622 — CI must never
# silently pass a scenario whose step definition doesn't exist.
# Every file declaring a `godog.Options{` block must contain a
# `Strict:` field (set to true). We grep for the field presence, not
# the literal `Strict: true` so that a commented-out Strict line still
# trips the check (cannot be disabled by accident).
check-bdd-strict:
	@FAILING=""; \
	for f in $$(grep -rln 'godog\.Options{' --include='*.go'); do \
		if ! grep -q 'Strict:' "$$f"; then \
			FAILING="$$FAILING $$f"; \
		fi; \
	done; \
	if [ -n "$$FAILING" ]; then \
		echo "ERROR: godog runners missing Strict: true (undefined steps would silently pass):"; \
		for f in $$FAILING; do echo "  $$f"; done; \
		echo ""; \
		echo "Every godog.Options{} block must set Strict: true. See #622."; \
		exit 1; \
	fi
	@echo "All godog runners use Strict mode."

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

check: fmt-check vet-all lint-all test-all build-all test-examples tidy-check verify check-replace check-todos check-bdd-strict release-check security
	@echo ""
	@echo "All checks passed."

# --- Clean ---

clean:
	go clean -testcache
	@for mod in $(MODULES); do \
		rm -f $$mod/coverage.out $$mod/coverage.html; \
	done
	rm -f bench.txt

# --- SBOM generation ---

SBOM_DIR := sbom

sbom:
	@mkdir -p $(SBOM_DIR)
	@echo "=== Generating CycloneDX SBOM (all modules) ==="
	@syft dir:. --output cyclonedx-json --file $(SBOM_DIR)/audit_sbom.cdx.json
	@echo "=== Generating SPDX SBOM (all modules) ==="
	@syft dir:. --output spdx-json --file $(SBOM_DIR)/audit_sbom.spdx.json
	@echo "SBOMs generated in $(SBOM_DIR)/"

sbom-validate:
	@echo "=== Validating CycloneDX SBOM ==="
	@python3 -c "import json; json.load(open('$(SBOM_DIR)/audit_sbom.cdx.json')); print('CycloneDX: valid JSON')"
	@echo "=== Validating SPDX SBOM ==="
	@python3 -c "import json; json.load(open('$(SBOM_DIR)/audit_sbom.spdx.json')); print('SPDX: valid JSON')"

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

# Per-service infrastructure targets for parallel CI runners.
# Each creates the shared network, starts only what it needs, and tears down cleanly.

test-infra-syslog-up:
	docker network create audit-test 2>/dev/null || true
	docker compose -f $(COMPOSE_DIR)/docker-compose.syslog.yml up -d --build --wait
	@echo "Syslog infrastructure is ready."

test-infra-syslog-down:
	docker compose -f $(COMPOSE_DIR)/docker-compose.syslog.yml down -v
	docker network rm audit-test 2>/dev/null || true

test-infra-webhook-up:
	docker network create audit-test 2>/dev/null || true
	docker compose -f $(COMPOSE_DIR)/docker-compose.webhook.yml up -d --build --wait
	@echo "Webhook infrastructure is ready."

test-infra-webhook-down:
	docker compose -f $(COMPOSE_DIR)/docker-compose.webhook.yml down -v
	docker network rm audit-test 2>/dev/null || true

test-infra-loki-up:
	docker network create audit-test 2>/dev/null || true
	docker compose -f $(COMPOSE_DIR)/docker-compose.loki.yml up -d --build --wait
	@echo "Loki infrastructure is ready."

test-infra-loki-down:
	docker compose -f $(COMPOSE_DIR)/docker-compose.loki.yml down -v
	docker network rm audit-test 2>/dev/null || true

test-infra-openbao-up:
	docker network create audit-test 2>/dev/null || true
	docker compose -f $(COMPOSE_DIR)/docker-compose.openbao.yml up -d --wait
	@echo "OpenBao infrastructure is ready."

test-infra-openbao-down:
	docker compose -f $(COMPOSE_DIR)/docker-compose.openbao.yml down -v
	docker network rm audit-test 2>/dev/null || true

test-infra-vault-up:
	docker network create audit-test 2>/dev/null || true
	docker compose -f $(COMPOSE_DIR)/docker-compose.vault.yml up -d --wait
	@echo "Vault infrastructure is ready."

test-infra-vault-down:
	docker compose -f $(COMPOSE_DIR)/docker-compose.vault.yml down -v
	docker network rm audit-test 2>/dev/null || true

# --- Publish verification (issue #29) ---

# Module definitions for publish targets: directory|module_path|tag_prefix
PUBLISH_MODULES := \
  .|github.com/axonops/audit| \
  file|github.com/axonops/audit/file|file/ \
  syslog|github.com/axonops/audit/syslog|syslog/ \
  webhook|github.com/axonops/audit/webhook|webhook/ \
  loki|github.com/axonops/audit/loki|loki/ \
  outputconfig|github.com/axonops/audit/outputconfig|outputconfig/ \
  outputs|github.com/axonops/audit/outputs|outputs/ \
  cmd/audit-gen|github.com/axonops/audit/cmd/audit-gen|cmd/audit-gen/ \
  secrets|github.com/axonops/audit/secrets|secrets/ \
  secrets/openbao|github.com/axonops/audit/secrets/openbao|secrets/openbao/ \
  secrets/vault|github.com/axonops/audit/secrets/vault|secrets/vault/

.PHONY: publish-trigger publish-verify publish-smoke

publish-trigger: ## Trigger proxy.golang.org indexing for VERSION (e.g. make publish-trigger VERSION=v0.1.1)
ifndef VERSION
	$(error VERSION is required, e.g. make publish-trigger VERSION=v0.1.1)
endif
	@for entry in $(PUBLISH_MODULES); do \
		mod=$$(echo "$$entry" | cut -d'|' -f2); \
		echo "Indexing $$mod@$(VERSION) ..."; \
		GOPROXY=https://proxy.golang.org go list -m "$$mod@$(VERSION)"; \
		echo "  ✓ $$mod@$(VERSION)"; \
	done

publish-verify: ## Verify modules on proxy.golang.org and pkg.go.dev for VERSION
ifndef VERSION
	$(error VERSION is required, e.g. make publish-verify VERSION=v0.1.1)
endif
	@for entry in $(PUBLISH_MODULES); do \
		mod=$$(echo "$$entry" | cut -d'|' -f2); \
		proxy_path=$$(echo "$$mod" | tr '[:upper:]' '[:lower:]'); \
		echo "Verifying $$mod@$(VERSION) ..."; \
		curl -sS --fail "https://proxy.golang.org/$${proxy_path}/@v/$(VERSION).info" > /dev/null || \
			{ echo "  ✗ proxy.golang.org FAILED for $$mod"; exit 1; }; \
		echo "  ✓ proxy.golang.org"; \
		status=$$(curl -sS -o /dev/null -w "%{http_code}" "https://pkg.go.dev/$${mod}@$(VERSION)"); \
		if [ "$$status" = "200" ]; then echo "  ✓ pkg.go.dev"; else echo "  ⚠ pkg.go.dev HTTP $$status (may still be indexing)"; fi; \
	done

publish-smoke: ## Smoke test: go get + compile all modules for VERSION
ifndef VERSION
	$(error VERSION is required, e.g. make publish-smoke VERSION=v0.1.1)
endif
	@dir=$$(mktemp -d) && \
	trap 'rm -rf "$$dir"' EXIT && \
	cd "$$dir" && \
	go mod init smoketest && \
	echo "Installing modules ..." && \
	go get "github.com/axonops/audit@$(VERSION)" && \
	go get "github.com/axonops/audit/file@$(VERSION)" && \
	go get "github.com/axonops/audit/syslog@$(VERSION)" && \
	go get "github.com/axonops/audit/webhook@$(VERSION)" && \
	go get "github.com/axonops/audit/loki@$(VERSION)" && \
	go get "github.com/axonops/audit/outputconfig@$(VERSION)" && \
	go get "github.com/axonops/audit/outputs@$(VERSION)" && \
	go get "github.com/axonops/audit/cmd/audit-gen@$(VERSION)" && \
	go get "github.com/axonops/audit/secrets@$(VERSION)" && \
	go get "github.com/axonops/audit/secrets/openbao@$(VERSION)" && \
	go get "github.com/axonops/audit/secrets/vault@$(VERSION)" && \
	printf 'package main\n\nimport (\n\t_ "github.com/axonops/audit"\n\t_ "github.com/axonops/audit/file"\n\t_ "github.com/axonops/audit/syslog"\n\t_ "github.com/axonops/audit/webhook"\n\t_ "github.com/axonops/audit/loki"\n\t_ "github.com/axonops/audit/outputconfig"\n\t_ "github.com/axonops/audit/outputs"\n\t_ "github.com/axonops/audit/secrets"\n\t_ "github.com/axonops/audit/secrets/openbao"\n\t_ "github.com/axonops/audit/secrets/vault"\n)\n\nfunc main() {}\n' > main.go && \
	go build -o /dev/null . && \
	go install "github.com/axonops/audit/cmd/audit-gen@$(VERSION)" && \
	echo "✓ All modules compile successfully"
