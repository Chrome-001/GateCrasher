// Deliberately vulnerable REST API for testing GateCrasher.
// DO NOT deploy in production.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// User represents an application user.
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Password string `json:"-"`
}

// Profile is the mutable profile for a user (mass-assignment target).
type Profile struct {
	UserID    int    `json:"user_id"`
	Bio       string `json:"bio"`
	AvatarURL string `json:"avatar_url"`
	Role      string `json:"role,omitempty"`      // intentionally writable
	IsAdmin   bool   `json:"is_admin,omitempty"` // intentionally writable
}

var users = []User{
	{ID: 1, Username: "admin", Email: "admin@example.com", Role: "admin", Password: "admin123"},
	{ID: 2, Username: "alice", Email: "alice@example.com", Role: "user", Password: "alice456"},
	{ID: 3, Username: "bob", Email: "bob@example.com", Role: "user", Password: "bob789"},
}

// tokenToUser resolves an Authorization: Bearer <token> header to a user.
func tokenToUser(r *http.Request) *User {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	for i := range users {
		if users[i].Password == token {
			return &users[i]
		}
	}
	return nil
}

// json helper
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// GET /api/users/{id}  — IDOR: no ownership check
func handleGetUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Any authenticated request gets any user — intentional IDOR
	_ = tokenToUser(r)

	idStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	idStr = strings.TrimSuffix(idStr, "/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	for _, u := range users {
		if u.ID == id {
			writeJSON(w, http.StatusOK, u)
			return
		}
	}
	writeError(w, http.StatusNotFound, "user not found")
}

// GET /api/admin/users — should require admin but accepts any token
func handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Intentional BAC: we check that *some* token is present but never verify role
	caller := tokenToUser(r)
	if caller == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	// BUG: should check caller.Role == "admin" but doesn't
	writeJSON(w, http.StatusOK, users)
}

// POST /api/users/{id}/profile — mass assignment: accepts role/is_admin fields
func handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	caller := tokenToUser(r)
	if caller == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Parse path: /api/users/{id}/profile
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}
	id, err := strconv.Atoi(parts[2])
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var profile Profile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Intentional mass assignment: reflect whatever the caller sends back
	profile.UserID = id
	writeJSON(w, http.StatusOK, profile)
}

// GET /api/files?path=  — path traversal
func handleFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	caller := tokenToUser(r)
	if caller == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		writeError(w, http.StatusBadRequest, "path parameter required")
		return
	}

	// Intentional path traversal: no sanitisation of the path parameter
	// Files are read relative to the working directory (or absolute)
	dataDir := "."
	fullPath := filepath.Join(dataDir, requestedPath)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("file not found: %v", err))
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write(data) //nolint:errcheck
}

// DELETE /api/users/{id} — responds 200 for all users regardless of token
func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Intentional BAC: any token can delete any user
	caller := tokenToUser(r)
	if caller == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	idStr = strings.TrimSuffix(idStr, "/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	for _, u := range users {
		if u.ID == id {
			// BUG: should check caller.ID == id || caller.Role == "admin"
			writeJSON(w, http.StatusOK, map[string]string{
				"message": fmt.Sprintf("user %d deleted", u.ID),
			})
			return
		}
	}
	writeError(w, http.StatusNotFound, "user not found")
}

// ── Router ────────────────────────────────────────────────────────────────────

func main() {
	mux := http.NewServeMux()

	// GET /api/users/{id}
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		parts := strings.Split(strings.Trim(path, "/"), "/")

		switch {
		// /api/users/{id}/profile  (POST)
		case len(parts) == 4 && parts[3] == "profile":
			handleUpdateProfile(w, r)

		// /api/users/{id}  (GET or DELETE)
		case len(parts) == 3:
			switch r.Method {
			case http.MethodGet:
				handleGetUser(w, r)
			case http.MethodDelete:
				handleDeleteUser(w, r)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}

		default:
			writeError(w, http.StatusNotFound, "not found")
		}
	})

	mux.HandleFunc("/api/admin/users", handleAdminUsers)
	mux.HandleFunc("/api/files", handleFiles)

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	addr := ":8080"
	log.Printf("Vulnerable API listening on %s", addr)
	log.Printf("Users: admin/admin123, alice/alice456, bob/bob789")
	log.Printf("Endpoints:")
	log.Printf("  GET    /api/users/{id}            — IDOR (no ownership check)")
	log.Printf("  GET    /api/admin/users            — BAC (any token accepted)")
	log.Printf("  POST   /api/users/{id}/profile     — Mass assignment")
	log.Printf("  GET    /api/files?path=<file>      — Path traversal")
	log.Printf("  DELETE /api/users/{id}             — BAC (any token can delete)")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
