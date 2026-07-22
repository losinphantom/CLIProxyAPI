package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testAgentIdentityCredential(t *testing.T) (credential, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}
	return credential{
		runtimeID:  "runtime-test",
		taskID:     "task-test",
		privateKey: base64.StdEncoding.EncodeToString(der),
	}, publicKey
}

func TestBuildAssertionParsesPKCS8AndSignsCanonicalEnvelope(t *testing.T) {
	credential, publicKey := testAgentIdentityCredential(t)
	now := time.Date(2026, time.July, 22, 1, 2, 3, 0, time.UTC)
	header, err := buildAssertion(credential, now)
	if err != nil {
		t.Fatalf("buildAssertion() error = %v", err)
	}
	if !strings.HasPrefix(header, "AgentAssertion ") {
		t.Fatalf("header = %q", header)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(header, "AgentAssertion "))
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	var envelope assertionEnvelope
	if err = json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	payload := envelope.AgentRuntimeID + ":" + envelope.TaskID + ":" + envelope.Timestamp
	if !ed25519.Verify(publicKey, []byte(payload), signature) {
		t.Fatal("signature did not verify")
	}
}
