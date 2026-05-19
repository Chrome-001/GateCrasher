package scanner

import (
	"context"
	"fmt"

	"github.com/gate-crasher/gate-crasher/internal/analyzer"
	"github.com/gate-crasher/gate-crasher/internal/engine"
)

// HTTPMethods is the full set of methods probed by MethodTamperScanner.
var HTTPMethods = []string{
	"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE",
}

// MethodTamperScanner tries all HTTP methods on an endpoint and flags unexpected 200s.
type MethodTamperScanner struct {
	Engine *engine.Engine
}

// Name returns the module identifier.
func (s *MethodTamperScanner) Name() string { return "method_tamper" }

// Run sends each HTTP method to the endpoint and flags successful responses
// on methods that were not in the baseline.
func (s *MethodTamperScanner) Run(ctx context.Context, target Target) ([]analyzer.Finding, error) {
	baseReq := BuildRequest(target)

	// Baseline using the declared method
	baseline := s.Engine.Do(ctx, baseReq)
	if baseline.Error != nil {
		return nil, fmt.Errorf("method tamper baseline: %w", baseline.Error)
	}

	var findings []analyzer.Finding

	for _, method := range HTTPMethods {
		if method == target.Method {
			continue // skip baseline method
		}

		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		req := cloneEngineRequest(baseReq)
		req.Method = method

		// HEAD and OPTIONS are low-risk; still probe them but don't include body
		if method == "HEAD" || method == "OPTIONS" {
			req.Body = ""
		}

		resp := s.Engine.Do(ctx, req)
		if resp.Error != nil {
			continue
		}

		isUnexpectedSuccess := resp.StatusCode >= 200 && resp.StatusCode < 300
		isTrace := method == "TRACE" && resp.StatusCode == 200

		if isUnexpectedSuccess || isTrace {
			sev := analyzer.SeverityMedium
			if method == "DELETE" || method == "PUT" || method == "TRACE" {
				sev = analyzer.SeverityHigh
			}
			desc := fmt.Sprintf(
				"Unexpected 200 on method %s for %s (baseline method: %s, baseline status: %d)",
				method, baseReq.URL, target.Method, baseline.StatusCode,
			)
			findings = append(findings, NewFinding(
				s.Name(),
				sev,
				baseReq.URL, method,
				desc,
				fmt.Sprintf("%s %s", method, baseReq.URL),
				analyzer.Snippet(resp.Body, 500),
			))
		}
	}

	return findings, nil
}

// methodTamperBaselineStatus returns a reasonable "expected" status for each
// method even before sending.  Used to provide context in descriptions.
func methodTamperBaselineStatus(method string) int {
	switch method {
	case "OPTIONS":
		return 200
	case "HEAD":
		return 200
	default:
		return 405
	}
}

var _ = methodTamperBaselineStatus // suppress unused warning; kept for documentation

// UnexpectedMethodResponse returns true when the response to an alternate method
// represents a security issue.
func UnexpectedMethodResponse(method string, resp engine.Response) bool {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true
	}
	return false
}
