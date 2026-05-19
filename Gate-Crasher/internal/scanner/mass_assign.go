package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/gate-crasher/gate-crasher/internal/analyzer"
	"github.com/gate-crasher/gate-crasher/internal/engine"
	"github.com/gate-crasher/gate-crasher/internal/fuzzer"
)

// MassAssignScanner injects sensitive privilege-escalating fields into request
// bodies and detects when the server reflects or accepts them.
type MassAssignScanner struct {
	Engine *engine.Engine
}

// Name returns the module identifier.
func (s *MassAssignScanner) Name() string { return "mass_assign" }

// Run sends requests with injected sensitive fields and flags suspicious responses.
func (s *MassAssignScanner) Run(ctx context.Context, target Target) ([]analyzer.Finding, error) {
	// Mass assignment is only relevant for mutation methods
	method := strings.ToUpper(target.Method)
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return nil, nil
	}

	baseReq := BuildRequest(target)

	// Baseline – original body
	baseline := s.Engine.Do(ctx, baseReq)
	if baseline.Error != nil {
		return nil, fmt.Errorf("mass assign baseline: %w", baseline.Error)
	}

	variants := fuzzer.MassAssignVariants(baseReq)

	var findings []analyzer.Finding

	for _, v := range variants {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		resp := s.Engine.Do(ctx, v)
		if resp.Error != nil {
			continue
		}

		// Flag if response reflects any of the injected fields
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			for _, field := range fuzzer.SensitiveFields {
				if strings.Contains(resp.Body, `"`+field+`"`) ||
					strings.Contains(resp.Body, field+":") {

					desc := fmt.Sprintf(
						"Mass assignment: injected field %q reflected in response for %s %s (status %d)",
						field, v.Method, v.URL, resp.StatusCode,
					)
					sev := analyzer.SeverityHigh
					if field == "is_admin" || field == "role" || field == "admin" {
						sev = analyzer.SeverityCritical
					}
					findings = append(findings, NewFinding(
						s.Name(),
						sev,
						v.URL, v.Method,
						desc,
						fmt.Sprintf("%s %s\nBody: %s", v.Method, v.URL, v.Body),
						analyzer.Snippet(resp.Body, 500),
					))
					break
				}
			}

			// Also flag a successful response when the baseline was a 4xx
			if baseline.StatusCode >= 400 && resp.StatusCode < 300 {
				desc := fmt.Sprintf(
					"Mass assignment: status flip %d→%d with injected body for %s %s",
					baseline.StatusCode, resp.StatusCode, v.Method, v.URL,
				)
				findings = append(findings, NewFinding(
					s.Name(),
					analyzer.SeverityHigh,
					v.URL, v.Method,
					desc,
					fmt.Sprintf("%s %s\nBody: %s", v.Method, v.URL, v.Body),
					analyzer.Snippet(resp.Body, 500),
				))
			}
		}
	}

	return findings, nil
}
