package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const authorizationScheme = "AgentAssertion"

type credential struct {
	runtimeID   string
	taskID      string
	privateKey  string
	raw         map[string]any
	name        string
	identityKey string
	taskKey     string
}

type assertionEnvelope struct {
	AgentRuntimeID string `json:"agent_runtime_id"`
	TaskID         string `json:"task_id"`
	Timestamp      string `json:"timestamp"`
	Signature      string `json:"signature"`
}

func parsePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		default:
			return r
		}
	}, encoded)
	der, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		der, err = base64.RawStdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil, errors.New("agent identity private key is not valid base64")
		}
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("agent identity private key is not valid PKCS#8")
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("agent identity private key is not Ed25519")
	}
	return privateKey, nil
}

func buildAssertion(value credential, now time.Time) (string, error) {
	if strings.TrimSpace(value.runtimeID) == "" || strings.TrimSpace(value.taskID) == "" {
		return "", errors.New("agent identity runtime or task id is missing")
	}
	privateKey, err := parsePrivateKey(value.privateKey)
	if err != nil {
		return "", err
	}
	timestamp := now.UTC().Format(time.RFC3339)
	payload := value.runtimeID + ":" + value.taskID + ":" + timestamp
	signature := ed25519.Sign(privateKey, []byte(payload))
	raw, err := json.Marshal(assertionEnvelope{
		AgentRuntimeID: value.runtimeID,
		TaskID:         value.taskID,
		Timestamp:      timestamp,
		Signature:      base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		return "", errors.New("failed to serialize agent assertion")
	}
	return authorizationScheme + " " + base64.RawURLEncoding.EncodeToString(raw), nil
}
