# GateCrasher

```
  ██████╗  █████╗ ████████╗███████╗      ██████╗██████╗  █████╗ ███████╗██╗  ██╗███████╗██████╗
 ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝     ██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗
 ██║  ███╗███████║   ██║   █████╗       ██║     ██████╔╝███████║███████╗███████║█████╗  ██████╔╝
 ██║   ██║██╔══██║   ██║   ██╔══╝       ██║     ██╔══██╗██╔══██║╚════██║██╔══██║██╔══╝  ██╔══██╗
 ╚██████╔╝██║  ██║   ██║   ███████╗     ╚██████╗██║  ██║██║  ██║███████║██║  ██║███████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝      ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

**OWASP API1/A01 — Broken Access Control Scanner**

| | |
|---|---|
| **Version** | v1.0.0 |
| **Author** | Chrome-001 |
| **License** | MIT |
| **Language** | Go 1.21 |

---

## Overview

GateCrasher is a production-grade vulnerability scanner targeting **Broken Access Control (BAC)** — consistently ranked #1 in the OWASP Top 10. It automates detection of IDOR, privilege escalation, HTTP method tampering, mass assignment, JWT attacks, and path traversal across REST APIs.

---

## Features

| Module | What it detects |
|---|---|
| `idor` | Insecure Direct Object References — numeric/UUID ID substitution in paths, query params, and request bodies |
| `privilege` | Privilege escalation — low-privilege tokens accessing admin-only endpoints (403 → 200 flips) |
| `method_tamper` | HTTP method tampering — unexpected 2xx responses on GET/PUT/DELETE/PATCH/HEAD/OPTIONS/TRACE |
| `mass_assign` | Mass assignment — injected `role`, `is_admin`, `privilege`, `permissions` fields accepted by the server |
| `jwt` | JWT attacks — alg:none, weak HMAC secret brute-force, RS256→HS256 key confusion |
| `path_traversal` | Path traversal — `../`, `%2e%2e%2f`, `....//` sequences in paths and query params |

**Reports:** JSON · Dark-theme HTML · JUnit XML (CI/CD ready)

---

## Installation

```bash
git clone https://github.com/gate-crasher/gate-crasher
cd gate-crasher
make build
./bin/gate-crasher version
```

**Requirements:** Go 1.21+

---

## Usage

### Basic scan

```bash
./bin/gate-crasher scan --target http://api.example.com --tokens <token>
```

### Multiple tokens (low-priv first, admin last)

```bash
./bin/gate-crasher scan \
  --target http://api.example.com \
  --tokens alice_token,admin_token
```

### Select specific modules

```bash
./bin/gate-crasher scan \
  --target http://api.example.com \
  --tokens alice_token \
  --modules idor,jwt,privilege
```

### HTML report

```bash
./bin/gate-crasher scan \
  --target http://api.example.com \
  --tokens alice_token \
  --output html \
  --outfile report.html
```

### Interactive wizard

```bash
./bin/gate-crasher wizard
```

### All flags

```
--target       Target base URL (required)
--tokens       Auth tokens, comma-separated (low-priv first, admin last)
--modules      Modules to run (default: all)
--workers      Concurrent workers (default: 10)
--delay        Delay between requests in ms (default: 0)
--rate-limit   Max requests per second (default: 50, 0 = unlimited)
--output       Report format: json, html, junit (default: json)
--outfile      Output file path (default: stdout)
--depth        Crawl depth (default: 3)
--wordlist     Custom wordlist file for endpoint discovery
--timeout      HTTP request timeout (default: 30s)
--tls-skip     Skip TLS certificate verification
--verbose      Verbose debug output
```

---

## Testing Against the Built-in Vulnerable API

GateCrasher ships with a deliberately vulnerable REST API for safe, local testing.

**Terminal 1 — start the vulnerable API:**
```bash
make vuln-api
# Vulnerable API listening on :8080
```

**Terminal 2 — run the demo scan:**
```bash
make scan-demo
# Writes JSON report to /tmp/gatecrasher-demo.json
```

### Vulnerable endpoints

| Endpoint | Vulnerability |
|---|---|
| `GET /api/users/{id}` | IDOR — no ownership check |
| `GET /api/admin/users` | Privilege escalation — accepts any token |
| `DELETE /api/users/{id}` | Privilege escalation — no authz check |
| `POST /api/users/{id}/profile` | Mass assignment — accepts `role` field |
| `GET /api/files?path=` | Path traversal — reads arbitrary files |

**Test tokens:** `alice456` (user), `bob789` (user), `admin123` (admin)

### Manual verification with curl

```bash
# IDOR — alice reads bob's data
curl -H "Authorization: Bearer alice456" http://localhost:8080/api/users/3

# Privilege escalation — low-priv token on admin route
curl -H "Authorization: Bearer alice456" http://localhost:8080/api/admin/users

# Mass assignment — inject role field
curl -X POST \
  -H "Authorization: Bearer alice456" \
  -H "Content-Type: application/json" \
  -d '{"name":"alice","role":"admin"}' \
  http://localhost:8080/api/users/2/profile

# Path traversal
curl -H "Authorization: Bearer alice456" \
  "http://localhost:8080/api/files?path=../../../../etc/passwd"
```

---

## Running Tests

```bash
make test
```

The GateCrasher banner prints before each test package runs. All 35 unit tests cover the analyzer, config, fuzzer, and scanner modules.

---

## CI/CD Integration

GateCrasher exits with code `2` when CRITICAL or HIGH findings are detected, making it a drop-in CI/CD gate.

```yaml
# GitHub Actions example
- name: Run GateCrasher
  run: |
    ./bin/gate-crasher scan \
      --target ${{ env.API_URL }} \
      --tokens ${{ secrets.SCAN_TOKEN }} \
      --output junit \
      --outfile gatecrasher.xml
  continue-on-error: false

- name: Publish test results
  uses: mikepenz/action-junit-report@v4
  with:
    report_paths: gatecrasher.xml
```

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Clean — no findings |
| `1` | Runtime error |
| `2` | CRITICAL or HIGH findings found |

---

## Project Structure

```
Gate-Crasher/
├── cmd/gate-crasher/main.go        # Cobra CLI (scan, wizard, version)
├── internal/
│   ├── banner/banner.go            # Shared ASCII banner
│   ├── config/config.go            # Viper config (YAML + env + flags)
│   ├── engine/engine.go            # Worker pool, rate limiting, HTTP client
│   ├── fuzzer/fuzzer.go            # Attack variant generation
│   ├── analyzer/analyzer.go        # Levenshtein similarity, severity classification
│   ├── scanner/                    # One file per detection module
│   │   ├── scanner.go              # Scanner interface + shared types
│   │   ├── idor.go
│   │   ├── privilege.go
│   │   ├── method_tamper.go
│   │   ├── mass_assign.go
│   │   ├── jwt.go
│   │   └── path_traversal.go
│   ├── reporter/                   # JSON, HTML, JUnit writers
│   └── crawler/crawler.go          # OpenAPI parser + wordlist prober
├── testdata/vulnerable-api/main.go # Deliberately vulnerable test API
└── Makefile
```

---

## Makefile Targets

```bash
make build          # Build binary → bin/gate-crasher
make test           # Run all unit tests
make vuln-api       # Build and start the vulnerable test API on :8080
make scan-demo      # Full demo scan against localhost:8080
make clean          # Remove build artifacts
```

---

## Environment Variables

All flags can be set via environment variables with the `GC_` prefix:

```bash
export GC_TARGET=http://api.example.com
export GC_TOKENS=alice456,admin123
export GC_OUTPUT=html
./bin/gate-crasher scan
```

---

## Support

If you find Gate-Crasher useful, consider supporting development:

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue?logo=paypal)](https://paypal.me/chrome001)
[![Ko-fi](https://img.shields.io/badge/Support-Ko--fi-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/chrome001) 

---

## Author

**Chrome-001**
github.com/gate-crasher/gate-crasher
