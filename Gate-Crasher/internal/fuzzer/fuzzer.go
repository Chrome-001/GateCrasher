package fuzzer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/gate-crasher/gate-crasher/internal/engine"
)

var (
	numericSegRe = regexp.MustCompile(`/(\d+)(/|$)`)
	uuidSegRe    = regexp.MustCompile(`/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/|$)`)
)

// IDReplacements is the set of numeric values substituted for path IDs.
var IDReplacements = []string{"0", "-1", "2", "3", "9999", "99999", "../admin", "null"}

// UUIDReplacements replaces UUID path segments with these values.
var UUIDReplacements = []string{
	"00000000-0000-0000-0000-000000000000",
	"ffffffff-ffff-ffff-ffff-ffffffffffff",
	"11111111-1111-1111-1111-111111111111",
}

// SensitiveFields are fields injected for mass-assignment probing.
var SensitiveFields = []string{"role", "is_admin", "admin", "privilege", "permissions", "group", "access_level"}

// PathVariants returns URL variants with numeric/UUID path segments replaced.
func PathVariants(base engine.Request) []engine.Request {
	var variants []engine.Request

	// Numeric replacements
	for _, rep := range IDReplacements {
		newURL := numericSegRe.ReplaceAllStringFunc(base.URL, func(match string) string {
			// Preserve trailing slash if present
			suffix := ""
			if strings.HasSuffix(match, "/") {
				suffix = "/"
			}
			return "/" + rep + suffix
		})
		if newURL != base.URL {
			v := cloneRequest(base)
			v.URL = newURL
			variants = append(variants, v)
		}
	}

	// UUID replacements
	for _, rep := range UUIDReplacements {
		newURL := uuidSegRe.ReplaceAllStringFunc(base.URL, func(match string) string {
			suffix := ""
			if strings.HasSuffix(match, "/") {
				suffix = "/"
			}
			return "/" + rep + suffix
		})
		if newURL != base.URL {
			v := cloneRequest(base)
			v.URL = newURL
			variants = append(variants, v)
		}
	}

	return variants
}

// QueryVariants injects alternative user IDs into query parameters.
func QueryVariants(base engine.Request, altIDs []string) []engine.Request {
	parsed, err := url.Parse(base.URL)
	if err != nil {
		return nil
	}

	params := parsed.Query()
	var variants []engine.Request

	idParams := []string{"id", "user_id", "userId", "uid", "account_id", "accountId", "owner_id"}

	for _, param := range idParams {
		if _, exists := params[param]; exists {
			for _, alt := range altIDs {
				newParams := cloneParams(params)
				newParams.Set(param, alt)
				parsed.RawQuery = newParams.Encode()

				v := cloneRequest(base)
				v.URL = parsed.String()
				variants = append(variants, v)
			}
		}
	}

	return variants
}

// BodyVariants replaces owner/user_id fields in JSON bodies.
func BodyVariants(base engine.Request, altIDs []string) []engine.Request {
	if base.Body == "" {
		return nil
	}

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(base.Body), &obj); err != nil {
		return nil
	}

	ownerFields := []string{"owner_id", "user_id", "userId", "uid", "account_id", "accountId", "id"}
	var variants []engine.Request

	for _, field := range ownerFields {
		if _, exists := obj[field]; exists {
			for _, alt := range altIDs {
				newObj := cloneMap(obj)
				newObj[field] = alt
				data, err := json.Marshal(newObj)
				if err != nil {
					continue
				}
				v := cloneRequest(base)
				v.Body = string(data)
				variants = append(variants, v)
			}
		}
	}

	return variants
}

// HeaderVariants injects spoofed identity headers.
func HeaderVariants(base engine.Request, altIDs []string) []engine.Request {
	spoofHeaders := []string{
		"X-User-ID",
		"X-Forwarded-For",
		"X-Original-URL",
		"X-Rewrite-URL",
		"X-Custom-IP-Authorization",
		"X-Real-IP",
	}

	var variants []engine.Request
	for _, alt := range altIDs {
		for _, h := range spoofHeaders {
			v := cloneRequest(base)
			if v.Headers == nil {
				v.Headers = make(map[string]string)
			}
			v.Headers[h] = alt
			variants = append(variants, v)
		}
	}

	// Also try forwarded-for with private IP ranges
	ipValues := []string{"127.0.0.1", "::1", "10.0.0.1", "192.168.1.1"}
	for _, ip := range ipValues {
		v := cloneRequest(base)
		if v.Headers == nil {
			v.Headers = make(map[string]string)
		}
		v.Headers["X-Forwarded-For"] = ip
		variants = append(variants, v)
	}

	return variants
}

// MassAssignVariants injects sensitive fields into JSON bodies.
func MassAssignVariants(base engine.Request) []engine.Request {
	if base.Body == "" {
		// Try injecting into an empty JSON object
		var variants []engine.Request
		for _, field := range SensitiveFields {
			v := cloneRequest(base)
			v.Body = fmt.Sprintf(`{"%s": "admin"}`, field)
			if v.Headers == nil {
				v.Headers = make(map[string]string)
			}
			v.Headers["Content-Type"] = "application/json"
			variants = append(variants, v)
		}
		return variants
	}

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(base.Body), &obj); err != nil {
		return nil
	}

	var variants []engine.Request
	for _, field := range SensitiveFields {
		for _, val := range []interface{}{"admin", true, 1, "superuser"} {
			newObj := cloneMap(obj)
			newObj[field] = val
			data, err := json.Marshal(newObj)
			if err != nil {
				continue
			}
			v := cloneRequest(base)
			v.Body = string(data)
			variants = append(variants, v)
		}
	}

	return variants
}

// PathTraversalVariants injects traversal sequences into path segments and query params.
func PathTraversalVariants(base engine.Request) []engine.Request {
	sequences := []string{
		"../../../etc/passwd",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"../etc/passwd",
		"../../etc/passwd",
	}

	var variants []engine.Request

	// Inject into last path segment
	for _, seq := range sequences {
		v := cloneRequest(base)
		v.URL = base.URL + "/" + seq
		variants = append(variants, v)
	}

	// Inject into query params named "path", "file", "filename", "dir"
	parsed, err := url.Parse(base.URL)
	if err != nil {
		return variants
	}
	params := parsed.Query()
	traversalParams := []string{"path", "file", "filename", "dir", "document", "name", "page"}

	for _, param := range traversalParams {
		for _, seq := range sequences {
			newParams := cloneParams(params)
			newParams.Set(param, seq)
			newParsed := *parsed
			newParsed.RawQuery = newParams.Encode()
			v := cloneRequest(base)
			v.URL = newParsed.String()
			variants = append(variants, v)
		}
	}

	return variants
}

// AllVariants returns all variant types combined.
func AllVariants(base engine.Request, altIDs []string) []engine.Request {
	var all []engine.Request
	all = append(all, PathVariants(base)...)
	all = append(all, QueryVariants(base, altIDs)...)
	all = append(all, BodyVariants(base, altIDs)...)
	all = append(all, HeaderVariants(base, altIDs)...)
	return all
}

// cloneRequest deep-copies a Request.
func cloneRequest(r engine.Request) engine.Request {
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

func cloneParams(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[k] = cp
	}
	return out
}

func cloneMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
