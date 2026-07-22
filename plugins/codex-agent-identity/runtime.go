package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const defaultAuthBaseURL = "https://auth.openai.com/api/accounts"

type agentIdentityHost interface {
	getAuth(callbackID, authIndex string) (pluginapi.HostAuthGetResponse, error)
	saveAuth(callbackID, name string, raw json.RawMessage) error
	doHTTP(callbackID string, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error)
}

type agentIdentityRuntime struct {
	host        agentIdentityHost
	now         func() time.Time
	authBaseURL string
	locks       sync.Map
}

type taskRegistrationResponse struct {
	TaskID               string `json:"task_id"`
	TaskIDCamel          string `json:"taskId"`
	EncryptedTaskID      string `json:"encrypted_task_id"`
	EncryptedTaskIDCamel string `json:"encryptedTaskId"`
}

func newAgentIdentityRuntime(host agentIdentityHost) *agentIdentityRuntime {
	return &agentIdentityRuntime{host: host, now: time.Now, authBaseURL: defaultAuthBaseURL}
}

func (r *agentIdentityRuntime) lock(authIndex string) *sync.Mutex {
	candidate := &sync.Mutex{}
	actual, _ := r.locks.LoadOrStore(strings.TrimSpace(authIndex), candidate)
	lock, ok := actual.(*sync.Mutex)
	if !ok {
		return candidate
	}
	return lock
}

func (r *agentIdentityRuntime) authorization(ctx context.Context, callbackID, authIndex string) (string, error) {
	value, err := r.loadCredential(callbackID, authIndex)
	if err != nil {
		return "", err
	}
	if value.taskID == "" {
		value, err = r.ensureTask(ctx, callbackID, authIndex)
		if err != nil {
			return "", err
		}
	}
	return buildAssertion(value, r.now())
}

func (r *agentIdentityRuntime) ensureTask(ctx context.Context, callbackID, authIndex string) (credential, error) {
	lock := r.lock(authIndex)
	lock.Lock()
	defer lock.Unlock()
	value, err := r.loadCredential(callbackID, authIndex)
	if err != nil {
		return credential{}, err
	}
	if value.taskID != "" {
		return value, nil
	}
	taskID, err := r.registerTask(ctx, callbackID, authIndex, value)
	if err != nil {
		return credential{}, err
	}
	return r.persistTask(callbackID, value, taskID)
}

func (r *agentIdentityRuntime) loadCredential(callbackID, authIndex string) (credential, error) {
	if r == nil || r.host == nil {
		return credential{}, errors.New("agent identity host is unavailable")
	}
	response, err := r.host.getAuth(callbackID, strings.TrimSpace(authIndex))
	if err != nil {
		return credential{}, errors.New("agent identity credential could not be loaded")
	}
	var metadata map[string]any
	if err = json.Unmarshal(response.JSON, &metadata); err != nil {
		return credential{}, errors.New("agent identity credential JSON is invalid")
	}
	identity := metadata
	identityKey := ""
	for _, key := range []string{"agent_identity", "agentIdentity"} {
		if nested, ok := metadata[key].(map[string]any); ok {
			identity = nested
			identityKey = key
			break
		}
	}
	taskKey := "task_id"
	if _, ok := identity["taskId"]; ok || identityKey == "agentIdentity" {
		taskKey = "taskId"
	}
	value := credential{
		runtimeID:   firstString(identity, "agent_runtime_id", "agentRuntimeId"),
		taskID:      firstString(identity, "task_id", "taskId"),
		privateKey:  firstString(identity, "agent_private_key", "agentPrivateKey", "private_key_pkcs8_base64", "privateKeyPkcs8Base64", "private_key", "privateKey"),
		raw:         metadata,
		name:        strings.TrimSpace(response.Name),
		identityKey: identityKey,
		taskKey:     taskKey,
	}
	if value.runtimeID == "" || value.privateKey == "" || value.name == "" {
		return credential{}, errors.New("agent identity credential is missing required fields")
	}
	return value, nil
}

func (r *agentIdentityRuntime) persistTask(callbackID string, value credential, taskID string) (credential, error) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return credential{}, errors.New("agent identity task id is empty")
	}
	metadata := make(map[string]any, len(value.raw)+1)
	for key, item := range value.raw {
		metadata[key] = item
	}
	if value.identityKey == "" {
		metadata[value.taskKey] = taskID
	} else {
		nestedRaw, ok := value.raw[value.identityKey].(map[string]any)
		if !ok {
			return credential{}, errors.New("agent identity credential JSON is invalid")
		}
		nested := make(map[string]any, len(nestedRaw)+1)
		for key, item := range nestedRaw {
			nested[key] = item
		}
		nested[value.taskKey] = taskID
		metadata[value.identityKey] = nested
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return credential{}, errors.New("failed to serialize agent identity credential")
	}
	if err = r.host.saveAuth(callbackID, value.name, raw); err != nil {
		return credential{}, errors.New("failed to persist agent identity task")
	}
	value.raw = metadata
	value.taskID = taskID
	return value, nil
}

func firstString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := metadata[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (r *agentIdentityRuntime) recoverTask(ctx context.Context, callbackID, authIndex, authorization string, status int, body []byte) (bool, error) {
	if !isTaskInvalidResponse(status, body) {
		return false, nil
	}
	expectedTaskID, err := assertionTaskID(authorization)
	if err != nil {
		return false, err
	}
	lock := r.lock(authIndex)
	lock.Lock()
	defer lock.Unlock()
	value, err := r.loadCredential(callbackID, authIndex)
	if err != nil {
		return false, err
	}
	if value.taskID != "" && value.taskID != expectedTaskID {
		return true, nil
	}
	taskID, err := r.registerTask(ctx, callbackID, authIndex, value)
	if err != nil {
		return false, err
	}
	if _, err = r.persistTask(callbackID, value, taskID); err != nil {
		return false, err
	}
	return true, nil
}

func assertionTaskID(authorization string) (string, error) {
	prefix := authorizationScheme + " "
	if !strings.HasPrefix(authorization, prefix) {
		return "", errors.New("agent identity recovery token is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(authorization, prefix))
	if err != nil {
		return "", errors.New("agent identity recovery token is invalid")
	}
	var envelope assertionEnvelope
	if err = json.Unmarshal(raw, &envelope); err != nil || strings.TrimSpace(envelope.TaskID) == "" {
		return "", errors.New("agent identity recovery token is invalid")
	}
	return strings.TrimSpace(envelope.TaskID), nil
}

func isTaskInvalidResponse(status int, body []byte) bool {
	if status != http.StatusUnauthorized {
		return false
	}
	lower := strings.ToLower(string(body))
	compact := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "").Replace(lower)
	for _, marker := range []string{
		`"code":"invalid_task_id"`,
		`"code":"task_not_found"`,
		`"code":"task_expired"`,
		`"error":"invalid_task_id"`,
	} {
		if strings.Contains(compact, marker) {
			return true
		}
	}
	for _, marker := range []string{
		"invalid task_id", "invalid task id", "task_id is invalid", "task id is invalid",
		"task not found", "task expired", "unknown task_id", "unknown task id",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func (r *agentIdentityRuntime) registerTask(_ context.Context, callbackID, authIndex string, value credential) (string, error) {
	if r == nil || r.host == nil {
		return "", errors.New("agent identity host is unavailable")
	}
	privateKey, err := parsePrivateKey(value.privateKey)
	if err != nil {
		return "", err
	}
	timestamp := r.now().UTC().Format(time.RFC3339)
	signature := ed25519.Sign(privateKey, []byte(value.runtimeID+":"+timestamp))
	body, err := json.Marshal(map[string]string{
		"timestamp": timestamp,
		"signature": base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		return "", errors.New("failed to serialize agent task registration")
	}
	endpoint := strings.TrimRight(r.authBaseURL, "/") + "/v1/agent/" + url.PathEscape(value.runtimeID) + "/task/register"
	response, err := r.host.doHTTP(callbackID, pluginapi.HTTPRequest{
		Method: http.MethodPost,
		URL:    endpoint,
		Headers: http.Header{
			"Accept":       []string{"application/json"},
			"Content-Type": []string{"application/json"},
		},
		Body: body,
	})
	if err != nil {
		return "", errors.New("agent task registration request failed")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("agent task registration returned status %d", response.StatusCode)
	}
	var result taskRegistrationResponse
	if err = json.Unmarshal(response.Body, &result); err != nil {
		return "", errors.New("agent task registration response is invalid")
	}
	for _, taskID := range []string{result.TaskID, result.TaskIDCamel} {
		if strings.TrimSpace(taskID) != "" {
			return strings.TrimSpace(taskID), nil
		}
	}
	encrypted := strings.TrimSpace(result.EncryptedTaskID)
	if encrypted == "" {
		encrypted = strings.TrimSpace(result.EncryptedTaskIDCamel)
	}
	if encrypted == "" {
		return "", errors.New("agent task registration response omitted task id")
	}
	return decryptTaskID(privateKey, encrypted)
}

func decryptTaskID(privateKey ed25519.PrivateKey, encoded string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", errors.New("encrypted agent task id is not valid base64")
	}
	digest := sha512.Sum512(privateKey.Seed())
	var curvePrivate [32]byte
	copy(curvePrivate[:], digest[:32])
	curvePrivate[0] &= 248
	curvePrivate[31] &= 127
	curvePrivate[31] |= 64
	curvePublicBytes, err := curve25519.X25519(curvePrivate[:], curve25519.Basepoint)
	if err != nil {
		return "", errors.New("failed to derive agent identity decryption key")
	}
	var curvePublic [32]byte
	copy(curvePublic[:], curvePublicBytes)
	plaintext, ok := box.OpenAnonymous(nil, ciphertext, &curvePublic, &curvePrivate)
	if !ok {
		return "", errors.New("failed to decrypt encrypted agent task id")
	}
	taskID := strings.TrimSpace(string(plaintext))
	if taskID == "" {
		return "", errors.New("decrypted agent task id is empty")
	}
	return taskID, nil
}
