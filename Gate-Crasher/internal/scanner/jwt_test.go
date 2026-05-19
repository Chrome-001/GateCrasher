package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJWTScannerName(t *testing.T) {
	s := &JWTScanner{Engine: newTestEngine()}
	if s.Name() != "jwt" {
		t.Errorf("expected name 'jwt', got %q", s.Name())
	}
}

func TestJWTScannerNoTokens(t *testing.T) {
	eng := newTestEngine()
	defer eng.Close()

	s := &JWTScanner{Engine: eng}
	target := Target{
		BaseURL:  "http://localhost",
		Method:   "GET",
		Endpoint: "/api/me",
		Tokens:   []string{},
	}
	findings, err := s.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings with no tokens, got %d", len(findings))
	}
}

func TestJWTScannerNonJWTToken(t *testing.T) {
	eng := newTestEngine()
	defer eng.Close()

	s := &JWTScanner{Engine: eng}
	target := Target{
		BaseURL:  "http://localhost",
		Method:   "GET",
		Endpoint: "/api/me",
		Tokens:   []string{"simple-api-key-not-a-jwt"},
	}
	findings, err := s.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for non-JWT token, got %d", len(findings))
	}
}

func TestAlgNoneToken(t *testing.T) {
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	none, err := algNoneToken(token)
	if err != nil {
		t.Fatalf("algNoneToken error: %v", err)
	}
	if !strings.HasSuffix(none, ".") {
		t.Errorf("expected alg:none token to have empty signature (trailing dot), got: %s", none)
	}
	parts := strings.Split(none, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 parts, got %d", len(parts))
	}
	if parts[2] != "" {
		t.Errorf("expected empty signature, got %q", parts[2])
	}
}

func TestForgeHMACToken(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	forged, err := forgeHMACToken(token, "secret")
	if err != nil {
		t.Fatalf("forgeHMACToken error: %v", err)
	}
	parts := strings.Split(forged, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 parts in forged JWT, got %d", len(parts))
	}
	if parts[2] == "" {
		t.Error("expected non-empty signature in forged JWT")
	}
}

func TestJWTScannerDetectsAlgNone(t *testing.T) {
	// Vulnerable server: accepts any bearer token including alg:none
	mux := http.NewServeMux()
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":1,"role":"admin"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	eng := newTestEngine()
	defer eng.Close()

	s := &JWTScanner{Engine: eng}
	// Use a valid-looking HS256 JWT
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	target := Target{
		BaseURL:  srv.URL,
		Method:   "GET",
		Endpoint: "/api/me",
		Tokens:   []string{token},
	}

	findings, err := s.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least one finding for vulnerable JWT server")
	}
	foundNone := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Description), "none") ||
			strings.Contains(strings.ToLower(f.Description), "weak") {
			foundNone = true
		}
	}
	if !foundNone {
		t.Errorf("expected alg:none or weak-secret finding, got: %v", findings)
	}
}
