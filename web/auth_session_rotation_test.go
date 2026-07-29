package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func responseAuthCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == authCookieName {
			return cookie
		}
	}
	t.Fatalf("response did not set %s cookie", authCookieName)
	return nil
}

func assertAuthCookieAttributes(t *testing.T, cookie *http.Cookie, maxAge int) {
	t.Helper()
	if cookie.Path != "/" {
		t.Errorf("cookie Path = %q, want /", cookie.Path)
	}
	if !cookie.HttpOnly {
		t.Error("cookie must be HttpOnly")
	}
	if !cookie.Secure {
		t.Error("cookie must be Secure for an HTTPS request")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite = %v, want Strict", cookie.SameSite)
	}
	if cookie.MaxAge != maxAge {
		t.Errorf("cookie MaxAge = %d, want %d", cookie.MaxAge, maxAge)
	}
}

func TestHandleChangePasswordSetsReplacementCookieForRotatedSecret(t *testing.T) {
	srv, password := testAdminServerWithAuth(t)
	oldSecret := append([]byte(nil), (*srv.jwtSecret.Load())...)
	oldToken, err := generateJWT("admin", oldSecret)
	if err != nil {
		t.Fatalf("generate old JWT: %v", err)
	}

	cfgPath := t.TempDir() + "/labyrinth.yaml"
	cfgContent := "web:\n  auth:\n    username: admin\n    password_hash: " + srv.config.Load().Web.Auth.PasswordHash + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	srv.SetConfigPath(cfgPath)

	body := `{"current_password":"` + password + `","new_password":"newSecurePass123"}`
	req := httptest.NewRequest(http.MethodPost, "https://example.test/api/auth/change-password", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleChangePassword(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("change password status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	cookie := responseAuthCookie(t, w)
	assertAuthCookieAttributes(t, cookie, authCookieMaxAge)
	if cookie.Value == "" {
		t.Fatal("replacement auth cookie is empty")
	}

	newSecret := *srv.jwtSecret.Load()
	if _, err := validateJWT(oldToken, newSecret, &srv.revokedTokens); err == nil {
		t.Fatal("JWT signed with pre-rotation secret remained valid")
	}
	username, err := validateJWT(cookie.Value, newSecret, &srv.revokedTokens)
	if err != nil {
		t.Fatalf("replacement cookie is invalid under rotated secret: %v", err)
	}
	if username != "admin" {
		t.Errorf("replacement cookie subject = %q, want admin", username)
	}
}

func TestHandleChangePasswordPartialResultStillSetsReplacementCookie(t *testing.T) {
	srv, password := testAdminServerWithAuth(t)
	srv.SetConfigPath(t.TempDir() + "/missing/labyrinth.yaml")

	body := `{"current_password":"` + password + `","new_password":"newSecurePass123"}`
	req := httptest.NewRequest(http.MethodPost, "https://example.test/api/auth/change-password", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleChangePassword(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("change password status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["status"] != "partial" {
		t.Fatalf("status = %v, want partial", response["status"])
	}

	cookie := responseAuthCookie(t, w)
	assertAuthCookieAttributes(t, cookie, authCookieMaxAge)
	if _, err := validateJWT(cookie.Value, *srv.jwtSecret.Load(), &srv.revokedTokens); err != nil {
		t.Fatalf("partial-success replacement cookie is invalid under rotated secret: %v", err)
	}
}

func TestHandleLogoutRevokesOnlyVerifiedJWT(t *testing.T) {
	t.Run("valid token is revoked", func(t *testing.T) {
		srv, _ := testAdminServerWithAuth(t)
		secret := *srv.jwtSecret.Load()
		token, err := generateJWT("admin", secret)
		if err != nil {
			t.Fatalf("generate JWT: %v", err)
		}
		payload, err := validateJWTPayload(token, secret, nil)
		if err != nil {
			t.Fatalf("validate generated JWT: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "https://example.test/api/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		srv.handleLogout(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("logout status = %d, want 200", w.Code)
		}
		if _, revoked := srv.revokedTokens.Load(payload.Jti); !revoked {
			t.Fatal("verified JWT jti was not revoked")
		}
		cookie := responseAuthCookie(t, w)
		assertAuthCookieAttributes(t, cookie, -1)
		if cookie.Value != "" {
			t.Errorf("cleared cookie value = %q, want empty", cookie.Value)
		}
	})

	tests := []struct {
		name  string
		token func(t *testing.T, secret []byte, jti string) string
	}{
		{
			name: "forged signature",
			token: func(t *testing.T, _ []byte, jti string) string {
				t.Helper()
				payload, err := json.Marshal(jwtPayload{
					Sub: "admin",
					Iat: time.Now().Unix(),
					Exp: time.Now().Add(time.Hour).Unix(),
					Jti: jti,
				})
				if err != nil {
					t.Fatalf("marshal payload: %v", err)
				}
				signingInput := jwtHeaderB64 + "." + encodeSegment(payload)
				return signingInput + "." + signHS256(signingInput, []byte("attacker-controlled-secret"))
			},
		},
		{
			name: "expired token",
			token: func(t *testing.T, secret []byte, jti string) string {
				t.Helper()
				payload, err := json.Marshal(jwtPayload{
					Sub: "admin",
					Iat: time.Now().Add(-2 * time.Hour).Unix(),
					Exp: time.Now().Add(-time.Hour).Unix(),
					Jti: jti,
				})
				if err != nil {
					t.Fatalf("marshal payload: %v", err)
				}
				signingInput := jwtHeaderB64 + "." + encodeSegment(payload)
				return signingInput + "." + signHS256(signingInput, secret)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" clears cookie without revocation", func(t *testing.T) {
			srv, _ := testAdminServerWithAuth(t)
			jti := "attacker-chosen-jti"
			token := tt.token(t, *srv.jwtSecret.Load(), jti)

			req := httptest.NewRequest(http.MethodPost, "https://example.test/api/auth/logout", nil)
			req.AddCookie(&http.Cookie{Name: authCookieName, Value: token})
			w := httptest.NewRecorder()
			srv.handleLogout(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("logout status = %d, want 200", w.Code)
			}
			if _, revoked := srv.revokedTokens.Load(jti); revoked {
				t.Fatal("unverified or stale JWT added its attacker-controlled jti to revokedTokens")
			}
			cookie := responseAuthCookie(t, w)
			assertAuthCookieAttributes(t, cookie, -1)
			if cookie.Value != "" {
				t.Errorf("cleared cookie value = %q, want empty", cookie.Value)
			}
		})
	}
}

func TestHandleLoginUsesSharedAuthCookieAttributes(t *testing.T) {
	srv, password := testAdminServerWithAuth(t)
	body := `{"username":"admin","password":"` + password + `"}`
	req := httptest.NewRequest(http.MethodPost, "https://example.test/api/auth/login", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	cookie := responseAuthCookie(t, w)
	assertAuthCookieAttributes(t, cookie, authCookieMaxAge)
}
