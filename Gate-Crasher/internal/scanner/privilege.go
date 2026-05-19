package scanner

import (
	"context"
	"fmt"

	"github.com/gate-crasher/gate-crasher/internal/analyzer"
	"github.com/gate-crasher/gate-crasher/internal/engine"
)

// PrivilegeScanner replays admin-only endpoints with a low-privilege token.
type PrivilegeScanner struct {
	Engine *engine.Engine
}

// Name returns the module identifier.
func (s *PrivilegeScanner) Name() string { return "privilege" }

// Run checks whether admin-only endpoints are accessible with a low-priv token.
//
// The target is expected to carry at least two tokens:
//   - Tokens[0] – admin / high-privilege token
//   - Tokens[1] – low-privilege token
//
// The scanner sends the request with the admin token first (baseline), then
// replays it with the low-priv token.  If the low-priv response is 200/201/204
// when it should be 403/401, it is flagged.
func (s *PrivilegeScanner) Run(ctx context.Context, target Target) ([]analyzer.Finding, error) {
	if len(target.Tokens) < 2 {
		// Nothing to compare – skip silently
		return nil, nil
	}

	adminReq := BuildRequest(target)
	adminReq.Token = target.Tokens[0]

	lowPrivReq := cloneEngineRequest(adminReq)
	lowPrivReq.Token = target.Tokens[1]

	// Baseline with admin token
	adminResp := s.Engine.Do(ctx, adminReq)
	if adminResp.Error != nil {
		return nil, fmt.Errorf("privilege scanner admin request: %w", adminResp.Error)
	}

	// Only probe endpoints that the admin can actually reach
	if adminResp.StatusCode < 200 || adminResp.StatusCode >= 300 {
		return nil, nil
	}

	// Probe with low-priv token
	lowResp := s.Engine.Do(ctx, lowPrivReq)
	if lowResp.Error != nil {
		return nil, fmt.Errorf("privilege scanner low-priv request: %w", lowResp.Error)
	}

	var findings []analyzer.Finding

	if lowResp.StatusCode >= 200 && lowResp.StatusCode < 300 {
		desc := fmt.Sprintf(
			"Privilege escalation: admin endpoint %s %s returned %d with low-privilege token (expected 401/403)",
			adminReq.Method, adminReq.URL, lowResp.StatusCode,
		)
		findings = append(findings, NewFinding(
			s.Name(),
			analyzer.SeverityCritical,
			adminReq.URL, adminReq.Method,
			desc,
			fmt.Sprintf("%s %s [low-priv token]", lowPrivReq.Method, lowPrivReq.URL),
			analyzer.Snippet(lowResp.Body, 500),
		))
	}

	return findings, nil
}

func cloneEngineRequest(r engine.Request) engine.Request {
	clone := engine.Request{
		Method: r.Method,
		URL:    r.URL,
		Body:   r.Body,
		Token:  r.Token,
	}
	if r.Headers != nil {
		clone.Headers = make(map[string]string, len(r.Headers))
		for k, v := range r.Headers {
			clone.Headers[k] = v
		}
	}
	return clone
}
