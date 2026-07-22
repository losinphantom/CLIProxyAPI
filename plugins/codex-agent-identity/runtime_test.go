package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

type fakeHost struct {
	mu        sync.Mutex
	auth      pluginapi.HostAuthGetResponse
	doCalls   int
	do        func(pluginapi.HTTPRequest, int) (pluginapi.HTTPResponse, error)
	saveCalls int
}

func (h *fakeHost) getAuth(string, string) (pluginapi.HostAuthGetResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.auth
	out.JSON = append(json.RawMessage(nil), h.auth.JSON...)
	return out, nil
}

func (h *fakeHost) saveAuth(_ string, name string, raw json.RawMessage) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.saveCalls++
	h.auth.Name = name
	h.auth.JSON = append(json.RawMessage(nil), raw...)
	return nil
}

func (h *fakeHost) doHTTP(_ string, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	h.mu.Lock()
	h.doCalls++
	call := h.doCalls
	do := h.do
	h.mu.Unlock()
	return do(req, call)
}

func rawCredential(t *testing.T, value credential) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"type":              "codex",
		"auth_kind":         "agent_identity",
		"agent_runtime_id":  value.runtimeID,
		"agent_private_key": value.privateKey,
		"task_id":           value.taskID,
	})
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	return raw
}

func TestRegisterTaskAcceptsPlaintextAndSealedBoxResponses(t *testing.T) {
	value, publicKey := testAgentIdentityCredential(t)
	value.taskID = ""
	privateKey, err := parsePrivateKey(value.privateKey)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	host := &fakeHost{auth: pluginapi.HostAuthGetResponse{Name: "agent.json", JSON: rawCredential(t, value)}}
	host.do = func(req pluginapi.HTTPRequest, call int) (pluginapi.HTTPResponse, error) {
		if req.Method != "POST" || !strings.HasSuffix(req.URL, "/v1/agent/runtime-test/task/register") {
			return pluginapi.HTTPResponse{}, fmt.Errorf("unexpected registration request: %s %s", req.Method, req.URL)
		}
		var registration map[string]string
		if errDecode := json.Unmarshal(req.Body, &registration); errDecode != nil {
			return pluginapi.HTTPResponse{}, errDecode
		}
		signature, errDecode := base64.StdEncoding.DecodeString(registration["signature"])
		if errDecode != nil || !ed25519.Verify(publicKey, []byte("runtime-test:"+registration["timestamp"]), signature) {
			return pluginapi.HTTPResponse{}, fmt.Errorf("registration signature did not verify")
		}
		if call == 1 {
			return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"task_id":"task-plain"}`)}, nil
		}
		digest := sha512.Sum512(privateKey.Seed())
		var curvePrivate [32]byte
		copy(curvePrivate[:], digest[:32])
		curvePrivate[0] &= 248
		curvePrivate[31] &= 127
		curvePrivate[31] |= 64
		curvePublicBytes, errX25519 := curve25519.X25519(curvePrivate[:], curve25519.Basepoint)
		if errX25519 != nil {
			return pluginapi.HTTPResponse{}, errX25519
		}
		var curvePublic [32]byte
		copy(curvePublic[:], curvePublicBytes)
		ciphertext, errSeal := box.SealAnonymous(nil, []byte("task-sealed"), &curvePublic, rand.Reader)
		if errSeal != nil {
			return pluginapi.HTTPResponse{}, errSeal
		}
		body := []byte(fmt.Sprintf(`{"encrypted_task_id":%q}`, base64.StdEncoding.EncodeToString(ciphertext)))
		return pluginapi.HTTPResponse{StatusCode: 200, Body: body}, nil
	}
	runtime := newAgentIdentityRuntime(host)
	runtime.now = func() time.Time { return time.Date(2026, 7, 22, 1, 2, 3, 0, time.UTC) }

	plain, err := runtime.registerTask(context.Background(), "callback", "idx", value)
	if err != nil || plain != "task-plain" {
		t.Fatalf("plaintext register = %q, %v", plain, err)
	}
	sealed, err := runtime.registerTask(context.Background(), "callback", "idx", value)
	if err != nil || sealed != "task-sealed" {
		t.Fatalf("sealed register = %q, %v", sealed, err)
	}
}

func TestAuthorizationRegistersAndPersistsMissingTaskOnceAcrossConcurrentRequests(t *testing.T) {
	value, _ := testAgentIdentityCredential(t)
	value.taskID = ""
	host := &fakeHost{auth: pluginapi.HostAuthGetResponse{Name: "agent.json", JSON: rawCredential(t, value)}}
	host.do = func(_ pluginapi.HTTPRequest, _ int) (pluginapi.HTTPResponse, error) {
		return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"task_id":"task-shared"}`)}, nil
	}
	runtime := newAgentIdentityRuntime(host)
	runtime.now = func() time.Time { return time.Date(2026, 7, 22, 1, 2, 3, 0, time.UTC) }

	start := make(chan struct{})
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			<-start
			_, err := runtime.authorization(context.Background(), "callback", "idx")
			errs <- err
		}()
	}
	close(start)
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatalf("authorization() error = %v", err)
		}
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.doCalls != 1 || host.saveCalls != 1 {
		t.Fatalf("calls = register:%d save:%d, want 1 and 1", host.doCalls, host.saveCalls)
	}
	var saved map[string]any
	if err := json.Unmarshal(host.auth.JSON, &saved); err != nil {
		t.Fatalf("unmarshal saved auth: %v", err)
	}
	if saved["task_id"] != "task-shared" {
		t.Fatalf("saved task_id = %#v", saved["task_id"])
	}
}

func TestRecoverTaskHandlesAllInvalidCodesAndPersistsReplacement(t *testing.T) {
	for _, code := range []string{"invalid_task_id", "task_not_found", "task_expired"} {
		t.Run(code, func(t *testing.T) {
			value, _ := testAgentIdentityCredential(t)
			value.taskID = "task-old"
			host := &fakeHost{auth: pluginapi.HostAuthGetResponse{Name: "agent.json", JSON: rawCredential(t, value)}}
			host.do = func(_ pluginapi.HTTPRequest, _ int) (pluginapi.HTTPResponse, error) {
				return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"task_id":"task-new"}`)}, nil
			}
			runtime := newAgentIdentityRuntime(host)
			runtime.now = func() time.Time { return time.Date(2026, 7, 22, 1, 2, 3, 0, time.UTC) }
			authorization, err := buildAssertion(value, runtime.now())
			if err != nil {
				t.Fatalf("build assertion: %v", err)
			}
			retry, err := runtime.recoverTask(context.Background(), "callback", "idx", authorization, 401, []byte(fmt.Sprintf(`{"error":{"code":%q}}`, code)))
			if err != nil || !retry {
				t.Fatalf("recoverTask() = %v, %v", retry, err)
			}
			host.mu.Lock()
			defer host.mu.Unlock()
			if host.doCalls != 1 || host.saveCalls != 1 || !strings.Contains(string(host.auth.JSON), "task-new") {
				t.Fatalf("host calls = register:%d save:%d json=%s", host.doCalls, host.saveCalls, host.auth.JSON)
			}
		})
	}
}

func TestRecoverTaskLockAvoidsDuplicateConcurrentRegistration(t *testing.T) {
	value, _ := testAgentIdentityCredential(t)
	value.taskID = "task-old"
	host := &fakeHost{auth: pluginapi.HostAuthGetResponse{Name: "agent.json", JSON: rawCredential(t, value)}}
	host.do = func(_ pluginapi.HTTPRequest, _ int) (pluginapi.HTTPResponse, error) {
		return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"task_id":"task-new"}`)}, nil
	}
	runtime := newAgentIdentityRuntime(host)
	runtime.now = func() time.Time { return time.Date(2026, 7, 22, 1, 2, 3, 0, time.UTC) }
	authorization, err := buildAssertion(value, runtime.now())
	if err != nil {
		t.Fatalf("build assertion: %v", err)
	}
	start := make(chan struct{})
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			<-start
			retry, errRecover := runtime.recoverTask(context.Background(), "callback", "idx", authorization, 401, []byte(`{"error":{"code":"invalid_task_id"}}`))
			if errRecover == nil && !retry {
				errRecover = fmt.Errorf("retry = false")
			}
			errs <- errRecover
		}()
	}
	close(start)
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatalf("recoverTask() error = %v", err)
		}
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.doCalls != 1 || host.saveCalls != 1 {
		t.Fatalf("calls = register:%d save:%d, want 1 and 1", host.doCalls, host.saveCalls)
	}
}

func TestAuthorizationBuildsFreshTimestampOnEveryCall(t *testing.T) {
	value, _ := testAgentIdentityCredential(t)
	host := &fakeHost{auth: pluginapi.HostAuthGetResponse{Name: "agent.json", JSON: rawCredential(t, value)}}
	runtime := newAgentIdentityRuntime(host)
	times := []time.Time{
		time.Date(2026, 7, 22, 1, 2, 3, 0, time.UTC),
		time.Date(2026, 7, 22, 1, 2, 4, 0, time.UTC),
	}
	clockCalls := 0
	runtime.now = func() time.Time {
		value := times[clockCalls]
		clockCalls++
		return value
	}
	first, err := runtime.authorization(context.Background(), "callback", "idx")
	if err != nil {
		t.Fatalf("first authorization: %v", err)
	}
	second, err := runtime.authorization(context.Background(), "callback", "idx")
	if err != nil {
		t.Fatalf("second authorization: %v", err)
	}
	if first == second {
		t.Fatal("successive assertions were reused")
	}
}

func TestAuthorizationErrorsNeverContainPrivateKeyMaterial(t *testing.T) {
	value, _ := testAgentIdentityCredential(t)
	value.privateKey = "secret-private-key-invalid!!!"
	host := &fakeHost{auth: pluginapi.HostAuthGetResponse{Name: "agent.json", JSON: rawCredential(t, value)}}
	_, err := newAgentIdentityRuntime(host).authorization(context.Background(), "callback", "idx")
	if err == nil {
		t.Fatal("authorization() error = nil")
	}
	if strings.Contains(err.Error(), value.privateKey) {
		t.Fatalf("authorization error leaked private key: %v", err)
	}
}
