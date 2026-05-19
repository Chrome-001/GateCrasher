package scanner

import (
	"context"
	"fmt"

	"github.com/gate-crasher/gate-crasher/internal/analyzer"
	"github.com/gate-crasher/gate-crasher/internal/engine"
	"github.com/gate-crasher/gate-crasher/internal/fuzzer"
)

// IDORScanner probes for Insecure Direct Object Reference vulnerabilities.
type IDORScanner struct {
	Engine *engine.Engine
}

// Name returns the module identifier.
func (s *IDORScanner) Name() string { return "idor" }

// Run executes IDOR probes against the target endpoint.
//
// Strategy:
//  1. Send the base request with the primary token (user A) → get baseline.
//  2. If a second token is present send the same request as user B to get the
//     "expected" response (what user A should NOT see).
//  3. Generate path/query/body variants replacing resource IDs.
//  4. Send each variant with user A's token.
//  5. Compare to user B's response; flag if content matches or a 403→200 flip
//     occurs.
func (s *IDORScanner) Run(ctx context.Context, target Target) ([]analyzer.Finding, error) {
	baseReq := BuildRequest(target)

	// Step 1 – baseline with token A
	baseline := s.Engine.Do(ctx, baseReq)
	if baseline.Error != nil {
		return nil, fmt.Errorf("idor baseline request: %w", baseline.Error)
	}

	// Step 2 – reference response with token B (if available)
	var userBResp *engine.Response
	if len(target.Tokens) >= 2 {
		reqB := baseReq
		reqB.Token = target.Tokens[len(target.Tokens)-1]
		resp := s.Engine.Do(ctx, reqB)
		if resp.Error == nil {
			userBResp = &resp
		}
	}

	altIDs := target.AltIDs
	if len(altIDs) == 0 {
		altIDs = []string{"1", "2", "3", "9999"}
	}

	// Step 3 – generate variants
	variants := fuzzer.PathVariants(baseReq)
	variants = append(variants, fuzzer.QueryVariants(baseReq, altIDs)...)
	variants = append(variants, fuzzer.BodyVariants(baseReq, altIDs)...)

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

		// Flag 403→200 flip
		if analyzer.IsPrivilegeEscalation(baseline, resp) {
			desc := fmt.Sprintf("IDOR: privilege escalation detected – baseline %d, variant %d at %s",
				baseline.StatusCode, resp.StatusCode, v.URL)
			findings = append(findings, NewFinding(
				s.Name(),
				analyzer.SeverityHigh,
				v.URL, v.Method,
				desc,
				fmt.Sprintf("%s %s", v.Method, v.URL),
				analyzer.Snippet(resp.Body, 500),
			))
			continue
		}

		// Flag if user B's response is suspiciously similar to our variant response
		if userBResp != nil && resp.StatusCode == 200 && userBResp.StatusCode == 200 {
			sim := analyzer.LevenshteinSimilarity(userBResp.Body, resp.Body)
			if sim > 0.80 {
				desc := fmt.Sprintf(
					"IDOR: response for variant URL %s matches user B response (similarity %.2f) – possible unauthorized access",
					v.URL, sim,
				)
				findings = append(findings, NewFinding(
					s.Name(),
					analyzer.SeverityHigh,
					v.URL, v.Method,
					desc,
					fmt.Sprintf("%s %s", v.Method, v.URL),
					analyzer.Snippet(resp.Body, 500),
				))
			}
		}
	}

	return findings, nil
}
