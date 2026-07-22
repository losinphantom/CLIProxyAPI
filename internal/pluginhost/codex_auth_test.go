package pluginhost

import (
	"context"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type codexAuthPluginStub struct {
	authorizationRequest pluginapi.CodexAuthAuthorizationRequest
	recoveryRequest      pluginapi.CodexAuthRecoveryRequest
}

func (p *codexAuthPluginStub) Match(metadata map[string]any) bool {
	kind, _ := metadata["auth_kind"].(string)
	return kind == "agent_identity"
}

func (p *codexAuthPluginStub) Authorization(_ context.Context, req pluginapi.CodexAuthAuthorizationRequest) (pluginapi.CodexAuthAuthorizationResponse, error) {
	p.authorizationRequest = req
	return pluginapi.CodexAuthAuthorizationResponse{Authorization: "AgentAssertion plugin"}, nil
}

func (p *codexAuthPluginStub) RecoverTask(_ context.Context, req pluginapi.CodexAuthRecoveryRequest) (pluginapi.CodexAuthRecoveryResponse, error) {
	p.recoveryRequest = req
	return pluginapi.CodexAuthRecoveryResponse{Retry: true}, nil
}

func TestHostCodexOutboundAuthDispatchesByMetadataAndAuthIndex(t *testing.T) {
	plugin := &codexAuthPluginStub{}
	host := newHostWithRecords(capabilityRecord{
		id: "agent-identity",
		plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{
			CodexAuth: plugin,
		}},
	})
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{ID: "agent", Index: "agent-index", Provider: "codex", Metadata: map[string]any{"auth_kind": "agent_identity"}}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}
	host.SetAuthManager(manager)

	if !host.Match(auth.Metadata) {
		t.Fatal("Match() = false, want true")
	}
	authorization, err := host.Authorization(context.Background(), auth.Index)
	if err != nil {
		t.Fatalf("Authorization() error = %v", err)
	}
	if authorization != "AgentAssertion plugin" || plugin.authorizationRequest.AuthIndex != auth.Index {
		t.Fatalf("authorization = %q request = %#v", authorization, plugin.authorizationRequest)
	}
	retry, err := host.RecoverTask(context.Background(), auth.Index, authorization, 401, []byte(`{"error":{"code":"invalid_task_id"}}`))
	if err != nil {
		t.Fatalf("RecoverTask() error = %v", err)
	}
	if !retry || plugin.recoveryRequest.Authorization != authorization || plugin.recoveryRequest.AuthIndex != auth.Index {
		t.Fatalf("retry = %v request = %#v", retry, plugin.recoveryRequest)
	}
}
