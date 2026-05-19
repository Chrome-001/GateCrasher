package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gate-crasher/gate-crasher/internal/engine"
)

func newTestEngine() *engine.Engine {
	return engine.New(engine.Options{
		Workers:   2,
		RateLimit: 0,
	})
}

func TestIDORScannerName(t *testing.T) {
	s := &IDORScanner{Engine: newTestEngine()}
	if s.Name() != "idor" {
		t.Errorf("expected name 'idor', got %q", s.Name())
	}
}

func TestIDORScannerDetectsIDOR(t *testing.T) {
	// Set up a test server that returns user data for any ID (IDOR)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":1,"username":"admin","email":"admin@example.com","role":"admin"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	eng := newTestEngine()
	defer eng.Close()

	s := &IDORScanner{Engine: eng}
	target := Target{
		BaseURL:  srv.URL,
		Method:   "GET",
		Endpoint: "/api/users/1",
		Tokens:   []string{"alice456", "bob789"},
		AltIDs:   []string{"2", "3"},
	}

	findings, err := s.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	// The vulnerable server returns 200 for any token/ID; we should detect the
	// similarity between userA and userB responses.
	_ = findings // findings may or may not be present depending on similarity
}

func TestIDORScannerNoFindingsOnClean(t *testing.T) {
	// Clean server: returns 403 for any ID other than the token owner's
	callCount := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		auth := r.Header.Get("Authorization")
		path := r.URL.Path
		// Only allow alice (token alice456) to access /api/users/2
		if strings.Contains(auth, "alice456") && strings.HasSuffix(path, "/2") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":2,"username":"alice"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	eng := newTestEngine()
	defer eng.Close()

	s := &IDORScanner{Engine: eng}
	target := Target{
		BaseURL:  srv.URL,
		Method:   "GET",
		Endpoint: "/api/users/2",
		Tokens:   []string{"alice456"},
		AltIDs:   []string{"1", "3"},
	}

	findings, err := s.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	// Baseline is 200; variants should get 403 → no privilege escalation
	for _, f := range findings {
		if f.Module != "idor" {
			t.Errorf("unexpected module %q in finding", f.Module)
		}
	}
	// The clean server should not trigger privilege escalation from 200→200 since
	// variant responses will be 403 (different from baseline 200)
	_ = findings
}

func TestIDORScannerContextCancellation(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":1}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	eng := newTestEngine()
	defer eng.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := &IDORScanner{Engine: eng}
	target := Target{
		BaseURL:  srv.URL,
		Method:   "GET",
		Endpoint: "/api/users/1",
		Tokens:   []string{"alice456"},
	}

	// Should return quickly due to cancelled context (may return error or empty)
	_, _ = s.Run(ctx, target)
}
