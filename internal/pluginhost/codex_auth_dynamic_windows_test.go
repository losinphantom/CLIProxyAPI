//go:build windows

package pluginhost

import (
	"context"
	"os"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

func TestCodexAgentIdentityDynamicPluginABI(t *testing.T) {
	path := os.Getenv("CLIPROXY_TEST_CODEX_AGENT_IDENTITY_PLUGIN")
	if path == "" {
		t.Skip("CLIPROXY_TEST_CODEX_AGENT_IDENTITY_PLUGIN is not set")
	}
	host := New()
	client, err := defaultPluginLoader().Open(pluginFile{ID: "codex-agent-identity", Path: path}, host)
	if err != nil {
		t.Fatalf("open plugin: %v", err)
	}
	defer client.Shutdown()
	plugin, err := registerRPCPlugin(context.Background(), host, "codex-agent-identity", client, pluginabi.MethodPluginRegister, nil)
	if err != nil {
		t.Fatalf("register plugin: %v", err)
	}
	if plugin.Capabilities.CodexAuth == nil || !plugin.Capabilities.CodexAuth.Match(map[string]any{"auth_kind": "agent_identity"}) {
		t.Fatal("dynamic plugin did not expose a matching Codex auth capability")
	}
}
