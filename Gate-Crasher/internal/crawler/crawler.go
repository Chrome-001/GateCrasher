package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Endpoint represents a discovered API endpoint.
type Endpoint struct {
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Summary     string            `json:"summary,omitempty"`
	Parameters  []Parameter       `json:"parameters,omitempty"`
	RequestBody string            `json:"request_body,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// Parameter represents an OpenAPI parameter.
type Parameter struct {
	Name     string `json:"name"`
	In       string `json:"in"` // path, query, header, cookie
	Required bool   `json:"required"`
	Schema   struct {
		Type   string      `json:"type"`
		Format string      `json:"format,omitempty"`
		Enum   interface{} `json:"enum,omitempty"`
	} `json:"schema,omitempty"`
}

// DefaultWordlist is a built-in set of common API paths.
var DefaultWordlist = []string{
	"/api/users",
	"/api/users/1",
	"/api/users/2",
	"/api/admin",
	"/api/admin/users",
	"/api/admin/settings",
	"/api/profile",
	"/api/me",
	"/api/account",
	"/api/accounts",
	"/api/orders",
	"/api/orders/1",
	"/api/items",
	"/api/items/1",
	"/api/products",
	"/api/products/1",
	"/api/files",
	"/api/documents",
	"/api/reports",
	"/api/settings",
	"/api/config",
	"/api/roles",
	"/api/permissions",
	"/api/groups",
	"/api/teams",
	"/api/invoices",
	"/api/payments",
	"/api/subscriptions",
	"/api/billing",
	"/api/logs",
}

// openAPIDoc is a minimal representation of an OpenAPI 3.0 spec.
type openAPIDoc struct {
	OpenAPI string                     `yaml:"openapi" json:"openapi"`
	Paths   map[string]openAPIPathItem `yaml:"paths" json:"paths"`
}

type openAPIPathItem map[string]openAPIOperation // key = HTTP method

type openAPIOperation struct {
	Summary     string          `yaml:"summary" json:"summary"`
	OperationID string          `yaml:"operationId" json:"operationId"`
	Parameters  []openAPIParam  `yaml:"parameters" json:"parameters"`
	RequestBody *openAPIReqBody `yaml:"requestBody" json:"requestBody"`
}

type openAPIParam struct {
	Name     string `yaml:"name" json:"name"`
	In       string `yaml:"in" json:"in"`
	Required bool   `yaml:"required" json:"required"`
	Schema   struct {
		Type   string `yaml:"type" json:"type"`
		Format string `yaml:"format" json:"format"`
	} `yaml:"schema" json:"schema"`
}

type openAPIReqBody struct {
	Content map[string]struct {
		Schema map[string]interface{} `yaml:"schema" json:"schema"`
	} `yaml:"content" json:"content"`
}

// ParseOpenAPI reads an OpenAPI 3.0 YAML or JSON spec and returns a list of
// discovered endpoints.
func ParseOpenAPI(path string) ([]Endpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading openapi spec %q: %w", path, err)
	}

	var doc openAPIDoc

	if strings.HasSuffix(strings.ToLower(path), ".json") {
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parsing openapi json: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parsing openapi yaml: %w", err)
		}
	}

	if doc.Paths == nil {
		return nil, fmt.Errorf("no paths found in openapi spec")
	}

	httpMethods := map[string]bool{
		"get": true, "post": true, "put": true, "delete": true,
		"patch": true, "head": true, "options": true,
	}

	var endpoints []Endpoint
	for path, pathItem := range doc.Paths {
		for method, op := range pathItem {
			if !httpMethods[strings.ToLower(method)] {
				continue
			}

			ep := Endpoint{
				Method:  strings.ToUpper(method),
				Path:    path,
				Summary: op.Summary,
			}

			for _, p := range op.Parameters {
				ep.Parameters = append(ep.Parameters, Parameter{
					Name:     p.Name,
					In:       p.In,
					Required: p.Required,
				})
			}

			endpoints = append(endpoints, ep)
		}
	}

	return endpoints, nil
}

// ProbeWordlist sends HEAD (falling back to GET) requests to each path and
// returns the ones that respond with a non-404, non-5xx status.
func ProbeWordlist(ctx context.Context, baseURL string, wordlist []string) ([]Endpoint, error) {
	if len(wordlist) == 0 {
		wordlist = DefaultWordlist
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	var found []Endpoint

	for _, p := range wordlist {
		select {
		case <-ctx.Done():
			return found, ctx.Err()
		default:
		}

		url := strings.TrimRight(baseURL, "/") + p

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "GateCrasher/1.0 (BAC-Scanner)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Treat anything except 404 / 5xx as "found"
		if resp.StatusCode != http.StatusNotFound &&
			resp.StatusCode < 500 {
			found = append(found, Endpoint{
				Method: "GET",
				Path:   p,
			})
		}
	}

	return found, nil
}
