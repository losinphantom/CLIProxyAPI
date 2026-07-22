package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type pluginRegistration struct {
	SchemaVersion uint32             `json:"schema_version"`
	Metadata      pluginapi.Metadata `json:"metadata"`
	Capabilities  pluginCapabilities `json:"capabilities"`
}

type pluginCapabilities struct {
	CodexAuth bool `json:"codex_auth"`
}

type authorizationRequest struct {
	pluginapi.CodexAuthAuthorizationRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type recoveryRequest struct {
	pluginapi.CodexAuthRecoveryRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

func handlePluginMethod(runtime *agentIdentityRuntime, method string, request []byte) (any, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return pluginRegistration{
			SchemaVersion: pluginabi.SchemaVersion,
			Metadata: pluginapi.Metadata{
				Name:             "codex-agent-identity",
				Version:          "0.1.0",
				Author:           "losinphantom",
				GitHubRepository: "https://github.com/losinphantom/CLIProxyAPI",
			},
			Capabilities: pluginCapabilities{CodexAuth: true},
		}, nil
	case pluginabi.MethodCodexAuthMatch:
		var req pluginapi.CodexAuthMatchRequest
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, errors.New("invalid Codex auth match request")
		}
		return pluginapi.CodexAuthMatchResponse{Matched: matchesAgentIdentity(req.AuthMetadata)}, nil
	case pluginabi.MethodCodexAuthAuthorization:
		var req authorizationRequest
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, errors.New("invalid Codex authorization request")
		}
		authorization, err := runtime.authorization(context.Background(), req.HostCallbackID, req.AuthIndex)
		if err != nil {
			return nil, err
		}
		return pluginapi.CodexAuthAuthorizationResponse{Authorization: authorization}, nil
	case pluginabi.MethodCodexAuthRecoverTask:
		var req recoveryRequest
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, errors.New("invalid Codex recovery request")
		}
		retry, err := runtime.recoverTask(context.Background(), req.HostCallbackID, req.AuthIndex, req.Authorization, req.Status, req.Body)
		if err != nil {
			return nil, err
		}
		return pluginapi.CodexAuthRecoveryResponse{Retry: retry}, nil
	case pluginabi.MethodPluginShutdown:
		return struct{}{}, nil
	default:
		return nil, errors.New("unknown plugin method")
	}
}

func matchesAgentIdentity(metadata map[string]any) bool {
	kind := firstString(metadata, "auth_kind")
	if strings.EqualFold(kind, "agent_identity") || strings.EqualFold(kind, "agent-identity") || strings.EqualFold(firstString(metadata, "type"), "agent_identity") {
		return true
	}
	return firstString(metadata, "agent_runtime_id") != "" && firstString(metadata, "agent_private_key", "private_key_pkcs8_base64", "private_key") != ""
}
