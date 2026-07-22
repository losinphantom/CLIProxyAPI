package management

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestDownloadAuthFile_ReturnsFile(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	fileName := "download-user.json"
	expected := []byte(`{"type":"codex"}`)
	if err := os.WriteFile(filepath.Join(authDir, fileName), expected, 0o600); err != nil {
		t.Fatalf("failed to write auth file: %v", err)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, nil)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/download?name="+url.QueryEscape(fileName), nil)
	h.DownloadAuthFile(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected download status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	if got := rec.Body.Bytes(); string(got) != string(expected) {
		t.Fatalf("unexpected download content: %q", string(got))
	}
}

func TestDownloadAuthFile_RedactsAgentIdentityPrivateKey(t *testing.T) {
	authDir := t.TempDir()
	fileName := "agent.json"
	privateKey := "private-key-must-not-leak"
	raw := []byte(`{"type":"codex","auth_kind":"agent_identity","agent_runtime_id":"runtime-test","agent_private_key":"` + privateKey + `"}`)
	path := filepath.Join(authDir, fileName)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, nil)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/download?name="+url.QueryEscape(fileName), nil)
	h.DownloadAuthFile(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), privateKey) || !strings.Contains(rec.Body.String(), "[redacted]") {
		t.Fatalf("download body was not redacted: %s", rec.Body.String())
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted auth: %v", err)
	}
	if !strings.Contains(string(persisted), privateKey) {
		t.Fatal("redaction modified persisted credential")
	}
}

func TestDownloadAuthFile_RedactsCamelCaseNestedAgentIdentityPrivateKey(t *testing.T) {
	authDir := t.TempDir()
	fileName := "agent-camel.json"
	privateKey := "private-key-must-not-leak"
	raw := []byte(`{"authMode":"agentIdentity","agentIdentity":{"agentRuntimeId":"runtime-test","agentPrivateKey":"` + privateKey + `","accountId":"account-test","chatgptUserId":"user-test"}}`)
	path := filepath.Join(authDir, fileName)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, nil)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/download?name="+url.QueryEscape(fileName), nil)
	h.DownloadAuthFile(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), privateKey) || !strings.Contains(rec.Body.String(), "[redacted]") {
		t.Fatalf("download body was not redacted: %s", rec.Body.String())
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted auth: %v", err)
	}
	if !strings.Contains(string(persisted), privateKey) {
		t.Fatal("redaction modified persisted credential")
	}
}

func TestDownloadAuthFile_RejectsPathSeparators(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, nil)

	for _, name := range []string{
		"../external/secret.json",
		`..\\external\\secret.json`,
		"nested/secret.json",
		`nested\\secret.json`,
	} {
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/download?name="+url.QueryEscape(name), nil)
		h.DownloadAuthFile(ctx)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected %d for name %q, got %d with body %s", http.StatusBadRequest, name, rec.Code, rec.Body.String())
		}
	}
}
