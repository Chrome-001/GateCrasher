package analyzer

import (
	"testing"

	"github.com/gate-crasher/gate-crasher/internal/engine"
)

func TestLevenshteinSimilarityIdentical(t *testing.T) {
	s := LevenshteinSimilarity("hello world", "hello world")
	if s != 1.0 {
		t.Errorf("identical strings: expected 1.0, got %f", s)
	}
}

func TestLevenshteinSimilarityEmpty(t *testing.T) {
	s := LevenshteinSimilarity("", "")
	if s != 1.0 {
		t.Errorf("both empty: expected 1.0, got %f", s)
	}
}

func TestLevenshteinSimilarityOneEmpty(t *testing.T) {
	s := LevenshteinSimilarity("hello", "")
	if s != 0.0 {
		t.Errorf("one empty: expected 0.0, got %f", s)
	}
}

func TestLevenshteinSimilarityPartial(t *testing.T) {
	s := LevenshteinSimilarity("kitten", "sitting")
	if s <= 0.0 || s >= 1.0 {
		t.Errorf("partial similarity for kitten/sitting: expected (0,1), got %f", s)
	}
}

func TestLevenshteinSimilarityHighSimilar(t *testing.T) {
	a := `{"id":1,"username":"alice","email":"alice@example.com","role":"user"}`
	b := `{"id":2,"username":"bob","email":"bob@example.com","role":"user"}`
	s := LevenshteinSimilarity(a, b)
	if s < 0.70 {
		t.Errorf("similar JSON responses: expected similarity > 0.70, got %f", s)
	}
}

func TestExtractIDsNumeric(t *testing.T) {
	body := `{"id":42,"user_id":1337,"data":"test"}`
	ids := ExtractIDs(body)
	if len(ids) == 0 {
		t.Error("expected numeric IDs to be extracted")
	}
	found42 := false
	for _, id := range ids {
		if id == "42" {
			found42 = true
		}
	}
	if !found42 {
		t.Errorf("expected id '42' in extracted IDs, got %v", ids)
	}
}

func TestExtractIDsUUID(t *testing.T) {
	body := `{"id":"550e8400-e29b-41d4-a716-446655440000","name":"test"}`
	ids := ExtractIDs(body)
	if len(ids) == 0 {
		t.Error("expected UUID to be extracted")
	}
	found := false
	for _, id := range ids {
		if id == "550e8400-e29b-41d4-a716-446655440000" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected UUID in extracted IDs, got %v", ids)
	}
}

func TestExtractIDsEmpty(t *testing.T) {
	ids := ExtractIDs("")
	if len(ids) != 0 {
		t.Errorf("empty body: expected no IDs, got %v", ids)
	}
}

func TestClassifyFindingCritical(t *testing.T) {
	f := Finding{
		Description: "JWT alg:none attack - jwt accepted with no signature",
	}
	sev := ClassifyFinding(f)
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL for JWT none attack, got %s", sev)
	}
}

func TestClassifyFindingHighIDOR(t *testing.T) {
	f := Finding{
		Description: "IDOR: accessed another user resource via privilege escalation",
	}
	sev := ClassifyFinding(f)
	if sev != SeverityHigh {
		t.Errorf("expected HIGH for IDOR, got %s", sev)
	}
}

func TestClassifyFindingMediumMethod(t *testing.T) {
	f := Finding{
		Description: "Unexpected 200 on method DELETE",
	}
	sev := ClassifyFinding(f)
	if sev != SeverityMedium {
		t.Errorf("expected MEDIUM for method finding, got %s", sev)
	}
}

func TestIsPrivilegeEscalation403to200(t *testing.T) {
	baseline := engine.Response{StatusCode: 403, Body: "Forbidden"}
	candidate := engine.Response{StatusCode: 200, Body: `{"id":1,"role":"admin"}`}
	if !IsPrivilegeEscalation(baseline, candidate) {
		t.Error("expected privilege escalation detected (403->200)")
	}
}

func TestIsPrivilegeEscalationNoEscalation(t *testing.T) {
	baseline := engine.Response{StatusCode: 403, Body: "Forbidden"}
	candidate := engine.Response{StatusCode: 403, Body: "Forbidden"}
	if IsPrivilegeEscalation(baseline, candidate) {
		t.Error("expected no privilege escalation (403->403)")
	}
}
