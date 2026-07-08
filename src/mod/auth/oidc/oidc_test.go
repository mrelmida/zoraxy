package oidc

import (
	"net/http"
	"path/filepath"
	"testing"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/database/dbinc"
	"imuslab.com/zoraxy/mod/info/logger"
)

func newTestRouter(t *testing.T, usernames ...string) *AdminOIDCRouter {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "test.db"), dbinc.BackendBoltDB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	l, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatal(err)
	}

	agent := auth.NewAuthenticationAgent("test", []byte("0123456789abcdef0123456789abcdef"), db, true, l, func(w http.ResponseWriter, r *http.Request) {})
	for _, username := range usernames {
		if err := agent.CreateUserAccount(username, "test-password", ""); err != nil {
			t.Fatal(err)
		}
	}

	return NewAdminOIDCRouter(&Options{
		Database:  db,
		Logger:    l,
		AuthAgent: agent,
	})
}

func TestResolveLocalUser(t *testing.T) {
	tests := []struct {
		name      string
		accounts  []string
		identity  string
		allowed   string
		mapToUser string
		wantUser  string
		wantErr   bool
	}{
		{
			name:     "allowlisted identity signs in as the only account",
			accounts: []string{"admin"},
			identity: "MrElmida",
			allowed:  "MrElmida, someone@example.com",
			wantUser: "admin",
		},
		{
			name:     "allowlisted email signs in as the only account",
			accounts: []string{"admin"},
			identity: "mrelmida@mindcraft-ce.com",
			allowed:  "mrelmida@mindcraft-ce.com",
			wantUser: "admin",
		},
		{
			name:     "allowlist match is case insensitive",
			accounts: []string{"admin"},
			identity: "mrelmida",
			allowed:  "MrElmida",
			wantUser: "admin",
		},
		{
			name:     "identity not on the allowlist is rejected",
			accounts: []string{"admin"},
			identity: "intruder",
			allowed:  "MrElmida",
			wantErr:  true,
		},
		{
			name:      "explicit MapToUser wins",
			accounts:  []string{"admin", "operator"},
			identity:  "MrElmida",
			allowed:   "MrElmida",
			mapToUser: "operator",
			wantUser:  "operator",
		},
		{
			name:      "MapToUser pointing at a missing account is rejected",
			accounts:  []string{"admin"},
			identity:  "MrElmida",
			allowed:   "MrElmida",
			mapToUser: "ghost",
			wantErr:   true,
		},
		{
			name:     "allowlisted claim matching a local account uses that account",
			accounts: []string{"admin", "mrelmida"},
			identity: "mrelmida",
			allowed:  "mrelmida",
			wantUser: "mrelmida",
		},
		{
			name:     "multiple accounts without mapping is ambiguous",
			accounts: []string{"admin", "operator"},
			identity: "MrElmida",
			allowed:  "MrElmida",
			wantErr:  true,
		},
		{
			name:     "no allowlist requires exact username match",
			accounts: []string{"admin"},
			identity: "admin",
			allowed:  "",
			wantUser: "admin",
		},
		{
			name:     "no allowlist rejects unknown identity",
			accounts: []string{"admin"},
			identity: "MrElmida",
			allowed:  "",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			router := newTestRouter(t, tc.accounts...)
			config := &Config{
				AllowedIdentities: tc.allowed,
				MapToUser:         tc.mapToUser,
			}
			gotUser, err := router.resolveLocalUser(tc.identity, config)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got user %q", gotUser)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotUser != tc.wantUser {
				t.Fatalf("expected user %q, got %q", tc.wantUser, gotUser)
			}
		})
	}
}
