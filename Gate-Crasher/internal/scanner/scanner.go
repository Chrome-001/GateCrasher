// Package scanner defines the Scanner interface and shared types used by all
// scan modules.
package scanner

import (
	"context"
	"time"

	"github.com/gate-crasher/gate-crasher/internal/analyzer"
	"github.com/gate-crasher/gate-crasher/internal/engine"
	"github.com/google/uuid"
)

// Target describes a single API endpoint to be tested.
type Target struct {
	BaseURL  string
	Method   string
	Headers  map[string]string
	Body     string
	Tokens   []string // index 0 = primary (low-priv), last = admin where applicable
	AltIDs   []string // alternative resource IDs to probe
	Endpoint string   // path relative to BaseURL, may contain {id} placeholders
}

// Scanner is the interface that every scan module must implement.
type Scanner interface {
	Name() string
	Run(ctx context.Context, target Target) ([]analyzer.Finding, error)
}

// newFinding creates a Finding with a fresh UUID and current timestamp.
func NewFinding(module string, sev analyzer.Severity, url, method, desc, req, snippet string) analyzer.Finding {
	return analyzer.Finding{
		ID:              uuid.New().String(),
		Module:          module,
		Severity:        sev,
		URL:             url,
		Method:          method,
		Description:     desc,
		Request:         req,
		ResponseSnippet: snippet,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	}
}

// BuildRequest creates an engine.Request from a Target.
func BuildRequest(t Target) engine.Request {
	token := ""
	if len(t.Tokens) > 0 {
		token = t.Tokens[0]
	}
	headers := make(map[string]string)
	for k, v := range t.Headers {
		headers[k] = v
	}
	return engine.Request{
		Method:  t.Method,
		URL:     t.BaseURL + t.Endpoint,
		Headers: headers,
		Body:    t.Body,
		Token:   token,
	}
}
