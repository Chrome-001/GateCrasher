.PHONY: build test vuln-api scan-demo lint clean

BINARY     := bin/gate-crasher
VULN_API   := bin/vulnerable-api
GO         := go
GOFLAGS    :=

# ── Build ─────────────────────────────────────────────────────────────────────
build:
	@mkdir -p bin
	$(GO) build $(GOFLAGS) -o $(BINARY) ./cmd/gate-crasher
	@echo "Built $(BINARY)"

# Build vulnerable test API
vuln-api-build:
	@mkdir -p bin
	$(GO) build $(GOFLAGS) -o $(VULN_API) ./testdata/vulnerable-api
	@echo "Built $(VULN_API)"

# ── Test ──────────────────────────────────────────────────────────────────────
test:
	$(GO) test ./... -v -timeout 60s

test-short:
	$(GO) test ./... -short -timeout 30s

# ── Run vulnerable API ────────────────────────────────────────────────────────
vuln-api: vuln-api-build
	@echo "Starting vulnerable API on :8080 (Ctrl-C to stop)"
	$(VULN_API)

# ── Demo scan ─────────────────────────────────────────────────────────────────
scan-demo: build
	@echo "Running demo scan against localhost:8080"
	./$(BINARY) scan \
		--target http://localhost:8080 \
		--tokens alice456,admin123 \
		--modules idor,privilege,mass_assign,path_traversal,jwt,method_tamper \
		--workers 5 \
		--output json \
		--outfile /tmp/gatecrasher-demo.json \
		--verbose
	@echo "Report written to /tmp/gatecrasher-demo.json"

# ── Lint ──────────────────────────────────────────────────────────────────────
lint:
	@which golangci-lint > /dev/null 2>&1 || (echo "golangci-lint not found; install from https://golangci-lint.run" && exit 1)
	golangci-lint run ./...

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	rm -rf bin/
	@echo "Cleaned"
