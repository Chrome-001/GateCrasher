package analyzer

import (
	"math"
	"regexp"
	"strings"

	"github.com/gate-crasher/gate-crasher/internal/engine"
)

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents a discovered vulnerability.
type Finding struct {
	ID              string   `json:"id"`
	Module          string   `json:"module"`
	Severity        Severity `json:"severity"`
	URL             string   `json:"url"`
	Method          string   `json:"method"`
	Description     string   `json:"description"`
	Request         string   `json:"request"`
	ResponseSnippet string   `json:"response_snippet"`
	Timestamp       string   `json:"timestamp"`
}

var (
	numericIDRe = regexp.MustCompile(`\b\d{1,10}\b`)
	uuidRe      = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
)

// LevenshteinSimilarity returns a similarity ratio in [0,1] between two strings.
// 1.0 = identical, 0.0 = completely different.
func LevenshteinSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	la, lb := len(a), len(b)
	if la == 0 && lb == 0 {
		return 1.0
	}
	if la == 0 || lb == 0 {
		return 0.0
	}

	// Limit to first 2000 chars for performance on large bodies
	const maxLen = 2000
	if la > maxLen {
		a = a[:maxLen]
		la = maxLen
	}
	if lb > maxLen {
		b = b[:maxLen]
		lb = maxLen
	}

	dist := levenshtein(a, b)
	maxLen2 := math.Max(float64(la), float64(lb))
	return 1.0 - float64(dist)/maxLen2
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)

	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = minInt(
				curr[j-1]+1,
				minInt(prev[j]+1, prev[j-1]+cost),
			)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// IsPrivilegeEscalation returns true when a candidate response suggests that a
// previously-forbidden resource is now accessible.
//
// Heuristics:
//   - baseline was 403/401 and candidate is 200/201/204
//   - both return 2xx and body similarity is > 0.85 (data leaked from another user)
func IsPrivilegeEscalation(baseline, candidate engine.Response) bool {
	baselineForbidden := baseline.StatusCode == 401 || baseline.StatusCode == 403
	candidateOK := candidate.StatusCode >= 200 && candidate.StatusCode < 300

	if baselineForbidden && candidateOK {
		return true
	}

	// Both 2xx but content is suspiciously similar (IDOR without ownership check)
	if candidate.StatusCode >= 200 && candidate.StatusCode < 300 &&
		baseline.StatusCode >= 200 && baseline.StatusCode < 300 {
		sim := LevenshteinSimilarity(baseline.Body, candidate.Body)
		if sim > 0.85 {
			return true
		}
	}

	return false
}

// ExtractIDs returns all numeric IDs and UUIDs found in body.
func ExtractIDs(body string) []string {
	seen := make(map[string]struct{})
	var out []string

	for _, m := range uuidRe.FindAllString(body, -1) {
		if _, ok := seen[m]; !ok {
			seen[m] = struct{}{}
			out = append(out, m)
		}
	}

	// Only include short numeric IDs that look like resource IDs (1-7 digits)
	re := regexp.MustCompile(`\b\d{1,7}\b`)
	for _, m := range re.FindAllString(body, -1) {
		if _, ok := seen[m]; !ok {
			seen[m] = struct{}{}
			out = append(out, m)
		}
	}

	return out
}

// ClassifyFinding assigns a severity based on the finding's description and URL.
// It uses the status codes encoded in the Finding description when possible.
func ClassifyFinding(f Finding) Severity {
	desc := strings.ToLower(f.Description)

	switch {
	case strings.Contains(desc, "none attack") ||
		strings.Contains(desc, "alg:none") ||
		strings.Contains(desc, "jwt accepted"):
		return SeverityCritical

	case strings.Contains(desc, "403") && strings.Contains(desc, "200"):
		return SeverityCritical

	case strings.Contains(desc, "admin") && strings.Contains(desc, "low"):
		return SeverityHigh

	case strings.Contains(desc, "privilege") ||
		strings.Contains(desc, "escalation") ||
		strings.Contains(desc, "idor"):
		return SeverityHigh

	case strings.Contains(desc, "mass assign") ||
		strings.Contains(desc, "role") ||
		strings.Contains(desc, "is_admin"):
		return SeverityHigh

	case strings.Contains(desc, "path traversal") ||
		strings.Contains(desc, "traversal") ||
		strings.Contains(desc, "../"):
		return SeverityHigh

	case strings.Contains(desc, "method") ||
		strings.Contains(desc, "unexpected 200"):
		return SeverityMedium

	case strings.Contains(desc, "information") ||
		strings.Contains(desc, "disclosure"):
		return SeverityLow

	default:
		return SeverityMedium
	}
}

// Snippet returns up to n bytes of body as a trimmed string.
func Snippet(body string, n int) string {
	if len(body) <= n {
		return strings.TrimSpace(body)
	}
	return strings.TrimSpace(body[:n]) + "..."
}
