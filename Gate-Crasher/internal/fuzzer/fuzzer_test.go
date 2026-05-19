package fuzzer

import (
	"strings"
	"testing"

	"github.com/gate-crasher/gate-crasher/internal/engine"
)

func TestPathVariantsNumeric(t *testing.T) {
	base := engine.Request{
		Method: "GET",
		URL:    "http://localhost:8080/api/users/1",
	}
	variants := PathVariants(base)
	if len(variants) == 0 {
		t.Fatal("expected path variants, got none")
	}
	// Original URL should not be in variants
	for _, v := range variants {
		if v.URL == base.URL {
			t.Errorf("variant URL should differ from base: %s", v.URL)
		}
	}
	// Should contain a variant with "9999"
	found := false
	for _, v := range variants {
		if strings.Contains(v.URL, "9999") {
			found = true
		}
	}
	if !found {
		t.Error("expected a variant with id=9999")
	}
}

func TestPathVariantsNoNumeric(t *testing.T) {
	base := engine.Request{
		Method: "GET",
		URL:    "http://localhost:8080/api/users",
	}
	variants := PathVariants(base)
	if len(variants) != 0 {
		t.Errorf("no numeric segments: expected 0 variants, got %d", len(variants))
	}
}

func TestQueryVariants(t *testing.T) {
	base := engine.Request{
		Method: "GET",
		URL:    "http://localhost:8080/api/data?user_id=1",
	}
	variants := QueryVariants(base, []string{"2", "3"})
	if len(variants) == 0 {
		t.Fatal("expected query variants, got none")
	}
	found2 := false
	for _, v := range variants {
		if strings.Contains(v.URL, "user_id=2") {
			found2 = true
		}
	}
	if !found2 {
		t.Error("expected variant with user_id=2")
	}
}

func TestBodyVariants(t *testing.T) {
	base := engine.Request{
		Method: "POST",
		URL:    "http://localhost:8080/api/items",
		Body:   `{"user_id": 1, "name": "test"}`,
	}
	variants := BodyVariants(base, []string{"2", "99"})
	if len(variants) == 0 {
		t.Fatal("expected body variants, got none")
	}
	found := false
	for _, v := range variants {
		if strings.Contains(v.Body, `"2"`) || strings.Contains(v.Body, "2") {
			found = true
		}
	}
	if !found {
		t.Error("expected body variant with user_id=2")
	}
}

func TestBodyVariantsNoBody(t *testing.T) {
	base := engine.Request{
		Method: "GET",
		URL:    "http://localhost:8080/api/items",
	}
	variants := BodyVariants(base, []string{"2"})
	if len(variants) != 0 {
		t.Errorf("no body: expected 0 body variants, got %d", len(variants))
	}
}

func TestMassAssignVariants(t *testing.T) {
	base := engine.Request{
		Method: "POST",
		URL:    "http://localhost:8080/api/users",
		Body:   `{"username": "alice", "email": "alice@example.com"}`,
	}
	variants := MassAssignVariants(base)
	if len(variants) == 0 {
		t.Fatal("expected mass-assign variants, got none")
	}
	foundRole := false
	for _, v := range variants {
		if strings.Contains(v.Body, `"role"`) {
			foundRole = true
		}
	}
	if !foundRole {
		t.Error("expected a variant injecting 'role' field")
	}
}

func TestHeaderVariants(t *testing.T) {
	base := engine.Request{
		Method: "GET",
		URL:    "http://localhost:8080/api/profile",
	}
	variants := HeaderVariants(base, []string{"2"})
	if len(variants) == 0 {
		t.Fatal("expected header variants, got none")
	}
	found := false
	for _, v := range variants {
		if v.Headers["X-User-ID"] == "2" {
			found = true
		}
	}
	if !found {
		t.Error("expected header variant with X-User-ID: 2")
	}
}

func TestPathTraversalVariants(t *testing.T) {
	base := engine.Request{
		Method: "GET",
		URL:    "http://localhost:8080/api/files?path=readme.txt",
	}
	variants := PathTraversalVariants(base)
	if len(variants) == 0 {
		t.Fatal("expected path traversal variants, got none")
	}
	foundTraversal := false
	for _, v := range variants {
		if strings.Contains(v.URL, "passwd") || strings.Contains(v.URL, "%2e%2e") ||
			strings.Contains(v.URL, "..") {
			foundTraversal = true
		}
	}
	if !foundTraversal {
		t.Error("expected at least one traversal variant")
	}
}
