package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type codexAuthSeamStub struct {
	match         bool
	authorization string
	authorize     func(context.Context, string) (string, error)
	recover       func(context.Context, string, string, int, []byte) (bool, error)
}

func (s *codexAuthSeamStub) Match(map[string]any) bool { return s.match }

func (s *codexAuthSeamStub) Authorization(ctx context.Context, authIndex string) (string, error) {
	if s.authorize != nil {
		return s.authorize(ctx, authIndex)
	}
	return s.authorization, nil
}

func (s *codexAuthSeamStub) RecoverTask(ctx context.Context, authIndex, authorization string, status int, body []byte) (bool, error) {
	if s.recover != nil {
		return s.recover(ctx, authIndex, authorization, status, body)
	}
	return false, nil
}

func TestCodexPrepareRequestLetsOutboundAuthSeamOverrideBearer(t *testing.T) {
	seam := &codexAuthSeamStub{match: true, authorization: "AgentAssertion fresh"}
	exec := NewCodexExecutor(nil, seam)
	auth := &cliproxyauth.Auth{
		ID:       "agent-auth",
		Index:    "agent-index",
		Provider: "codex",
		Metadata: map[string]any{
			"access_token":       "stale-bearer",
			"auth_kind":          "agent_identity",
			"agent_runtime_id":   "runtime-test",
			"agent_private_key":  "redacted-test-value",
			"chatgpt_account_id": "account-test",
		},
	}
	req, err := http.NewRequest(http.MethodPost, "https://example.test/responses", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	if err = exec.PrepareRequest(req, auth); err != nil {
		t.Fatalf("PrepareRequest() error = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "AgentAssertion fresh" {
		t.Fatalf("Authorization = %q, want AgentAssertion fresh", got)
	}
	if got := req.Header.Get("Chatgpt-Account-Id"); got != "account-test" {
		t.Fatalf("Chatgpt-Account-Id = %q", got)
	}
}

func TestCodexPrepareRequestUsesAccountIDFromNestedAgentIdentity(t *testing.T) {
	seam := &codexAuthSeamStub{match: true, authorization: "AgentAssertion fresh"}
	auth := &cliproxyauth.Auth{ID: "agent-auth", Index: "agent-index", Provider: "codex", Metadata: map[string]any{
		"auth_mode": "agentIdentity",
		"agent_identity": map[string]any{
			"agent_runtime_id":  "runtime-test",
			"agent_private_key": "private-key-present",
			"account_id":        "account-nested",
			"chatgpt_user_id":   "user-nested",
		},
	}}
	req, err := http.NewRequest(http.MethodPost, "https://example.test/responses", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err = NewCodexExecutor(nil, seam).PrepareRequest(req, auth); err != nil {
		t.Fatalf("PrepareRequest() error = %v", err)
	}
	if got := req.Header.Get("Chatgpt-Account-Id"); got != "account-nested" {
		t.Fatalf("Chatgpt-Account-Id = %q", got)
	}
}

func TestCodexPrepareRequestFailsClosedWithoutAgentIdentityPlugin(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.test/responses", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	auth := &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{
		"auth_kind":         "agent_identity",
		"agent_runtime_id":  "runtime-test",
		"agent_private_key": "private-key-present",
	}}
	if err = NewCodexExecutor(nil).PrepareRequest(req, auth); err == nil {
		t.Fatal("PrepareRequest() error = nil, want missing plugin error")
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want empty", got)
	}
}

func TestCodexHTTPRequestRecoversTaskOnceWithFreshAuthorization(t *testing.T) {
	var (
		mu              sync.Mutex
		receivedHeaders []string
		requestBodies   []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedHeaders = append(receivedHeaders, r.Header.Get("Authorization"))
		requestBodies = append(requestBodies, string(body))
		requestNumber := len(receivedHeaders)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if requestNumber == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"invalid_task_id"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	authorizationCalls := 0
	recoveryCalls := 0
	seam := &codexAuthSeamStub{match: true}
	seam.authorize = func(context.Context, string) (string, error) {
		authorizationCalls++
		return fmt.Sprintf("AgentAssertion request-%d", authorizationCalls), nil
	}
	seam.recover = func(_ context.Context, authIndex, authorization string, status int, body []byte) (bool, error) {
		recoveryCalls++
		if authIndex != "agent-index" || authorization != "AgentAssertion request-1" || status != http.StatusUnauthorized {
			t.Fatalf("RecoverTask() args = %q, %q, %d", authIndex, authorization, status)
		}
		if !bytes.Contains(body, []byte("invalid_task_id")) {
			t.Fatalf("RecoverTask() body = %s", body)
		}
		return true, nil
	}

	req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader(`{"input":"hello"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	auth := &cliproxyauth.Auth{
		ID:       "agent-auth",
		Index:    "agent-index",
		Provider: "codex",
		Metadata: map[string]any{"auth_kind": "agent_identity"},
	}
	resp, err := NewCodexExecutor(nil, seam).HttpRequest(context.Background(), auth, req)
	if err != nil {
		t.Fatalf("HttpRequest() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if authorizationCalls != 2 || recoveryCalls != 1 {
		t.Fatalf("calls = authorization:%d recovery:%d, want 2 and 1", authorizationCalls, recoveryCalls)
	}
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(receivedHeaders) != "[AgentAssertion request-1 AgentAssertion request-2]" {
		t.Fatalf("headers = %v", receivedHeaders)
	}
	if fmt.Sprint(requestBodies) != `[{"input":"hello"} {"input":"hello"}]` {
		t.Fatalf("request bodies = %v", requestBodies)
	}
}

func TestCodexHTTPRequestNeverRecoversOrRetriesMoreThanOnce(t *testing.T) {
	requestCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCalls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"invalid_task_id"}}`))
	}))
	defer server.Close()
	authorizationCalls := 0
	recoveryCalls := 0
	seam := &codexAuthSeamStub{match: true}
	seam.authorize = func(context.Context, string) (string, error) {
		authorizationCalls++
		return fmt.Sprintf("AgentAssertion request-%d", authorizationCalls), nil
	}
	seam.recover = func(context.Context, string, string, int, []byte) (bool, error) {
		recoveryCalls++
		return true, nil
	}
	req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader(`{"input":"hello"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	auth := &cliproxyauth.Auth{ID: "agent", Index: "idx", Provider: "codex", Metadata: map[string]any{"auth_kind": "agent_identity"}}
	resp, err := NewCodexExecutor(nil, seam).HttpRequest(context.Background(), auth, req)
	if err != nil {
		t.Fatalf("HttpRequest() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || requestCalls != 2 || authorizationCalls != 2 || recoveryCalls != 1 {
		t.Fatalf("status=%d calls=request:%d authorization:%d recovery:%d", resp.StatusCode, requestCalls, authorizationCalls, recoveryCalls)
	}
}

func TestCodexWebsocketDialRecoversTaskOnceWithFreshAuthorization(t *testing.T) {
	var (
		mu              sync.Mutex
		receivedHeaders []string
		upgrader        = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedHeaders = append(receivedHeaders, r.Header.Get("Authorization"))
		requestNumber := len(receivedHeaders)
		mu.Unlock()
		if requestNumber == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"task_expired"}}`))
			return
		}
		conn, errUpgrade := upgrader.Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade: %v", errUpgrade)
			return
		}
		_ = conn.Close()
	}))
	defer server.Close()

	authorizationCalls := 0
	recoveryCalls := 0
	seam := &codexAuthSeamStub{match: true}
	seam.authorize = func(context.Context, string) (string, error) {
		authorizationCalls++
		return fmt.Sprintf("AgentAssertion dial-%d", authorizationCalls), nil
	}
	seam.recover = func(_ context.Context, _ string, authorization string, status int, body []byte) (bool, error) {
		recoveryCalls++
		if authorization != "AgentAssertion dial-1" || status != http.StatusUnauthorized || !bytes.Contains(body, []byte("task_expired")) {
			t.Fatalf("RecoverTask() got authorization=%q status=%d body=%s", authorization, status, body)
		}
		return true, nil
	}
	auth := &cliproxyauth.Auth{ID: "agent-auth", Index: "agent-index", Provider: "codex", Metadata: map[string]any{"auth_kind": "agent_identity"}}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, resp, err := NewCodexWebsocketsExecutor(nil, seam).dialCodexWebsocket(context.Background(), auth, wsURL, http.Header{})
	if err != nil {
		t.Fatalf("dialCodexWebsocket() error = %v", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if conn == nil {
		t.Fatal("dialCodexWebsocket() conn is nil")
	}
	_ = conn.Close()
	if authorizationCalls != 2 || recoveryCalls != 1 {
		t.Fatalf("calls = authorization:%d recovery:%d, want 2 and 1", authorizationCalls, recoveryCalls)
	}
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(receivedHeaders) != "[AgentAssertion dial-1 AgentAssertion dial-2]" {
		t.Fatalf("headers = %v", receivedHeaders)
	}
}
