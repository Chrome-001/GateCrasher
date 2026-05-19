package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/gate-crasher/gate-crasher/internal/analyzer"
	"github.com/gate-crasher/gate-crasher/internal/engine"
	"github.com/gate-crasher/gate-crasher/internal/fuzzer"
)

var (
	// Patterns that indicate a successful path traversal hit.
	passwdRe   = regexp.MustCompile(`root:[x*]?:\d+`)
	etcPasswd  = regexp.MustCompile(`/etc/passwd`)
	winHostsRe = regexp.MustCompile(`\[drivers\]|\[fonts\]`)
	shadowRe   = regexp.MustCompile(`root:\$[0-9a-zA-Z$]+\$`)
)

// PathTraversalScanner injects directory traversal sequences to detect file
// disclosure vulnerabilities.
type PathTraversalScanner struct {
	Engine *engine.Engine
}

// Name returns the module identifier.
func (s *PathTraversalScanner) Name() string { return "path_traversal" }

// Run generates traversal variants and checks responses for sensitive content.
func (s *PathTraversalScanner) Run(ctx context.Context, target Target) ([]analyzer.Finding, error) {
	baseReq := BuildRequest(target)

	// Baseline
	baseline := s.Engine.Do(ctx, baseReq)
	if baseline.Error != nil {
		return nil, fmt.Errorf("path traversal baseline: %w", baseline.Error)
	}

	variants := fuzzer.PathTraversalVariants(baseReq)

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

		if isSensitiveContent(resp.Body) {
			desc := fmt.Sprintf(
				"Path traversal: sensitive file content detected in response for %s %s",
				v.Method, v.URL,
			)
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

		// Flag if the server returns 200 with a body substantially different from
		// the baseline – may indicate a file was read.
		if resp.StatusCode == 200 && baseline.StatusCode == 200 {
			sim := analyzer.LevenshteinSimilarity(baseline.Body, resp.Body)
			if sim < 0.10 && len(resp.Body) > 10 {
				desc := fmt.Sprintf(
					"Path traversal: low similarity (%.2f) with baseline suggests different file content for %s %s",
					sim, v.Method, v.URL,
				)
				findings = append(findings, NewFinding(
					s.Name(),
					analyzer.SeverityMedium,
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

// isSensitiveContent returns true if the body contains patterns indicative of
// file disclosure (e.g. /etc/passwd content).
func isSensitiveContent(body string) bool {
	return passwdRe.MatchString(body) ||
		etcPasswd.MatchString(body) ||
		winHostsRe.MatchString(body) ||
		shadowRe.MatchString(body) ||
		strings.Contains(body, "root:x:0:0") ||
		strings.Contains(body, "daemon:x:")
}

// PathTraversalDetected returns true if the engine response suggests a
// successful traversal.  Exported for use in tests.
func PathTraversalDetected(resp engine.Response) bool {
	return isSensitiveContent(resp.Body)
}
