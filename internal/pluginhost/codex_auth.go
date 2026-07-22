package pluginhost

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type codexAuthContextKey struct{}

func withCodexAuthContext(ctx context.Context, auth *coreauth.Auth) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, codexAuthContextKey{}, auth)
}

func codexAuthFromContext(ctx context.Context) *coreauth.Auth {
	if ctx == nil {
		return nil
	}
	auth, _ := ctx.Value(codexAuthContextKey{}).(*coreauth.Auth)
	return auth
}

// Match implements the executor's final outbound Codex authentication seam.
func (h *Host) Match(authMetadata map[string]any) bool {
	_, ok := h.codexAuthRecord(authMetadata)
	return ok
}

func (h *Host) Authorization(ctx context.Context, authIndex string) (string, error) {
	auth, record, err := h.codexAuthForIndex(authIndex)
	if err != nil {
		return "", err
	}
	ctx = withCodexAuthContext(ctx, auth)
	var response pluginapi.CodexAuthAuthorizationResponse
	if err = h.callCodexAuth(record, "CodexAuth.Authorization", func(provider pluginapi.CodexAuth) error {
		var errAuthorization error
		response, errAuthorization = provider.Authorization(ctx, pluginapi.CodexAuthAuthorizationRequest{AuthIndex: authIndex})
		return errAuthorization
	}); err != nil {
		return "", err
	}
	if strings.TrimSpace(response.Authorization) == "" {
		return "", fmt.Errorf("codex auth plugin returned empty authorization")
	}
	return response.Authorization, nil
}

func (h *Host) RecoverTask(ctx context.Context, authIndex, authorization string, status int, body []byte) (bool, error) {
	auth, record, err := h.codexAuthForIndex(authIndex)
	if err != nil {
		return false, err
	}
	ctx = withCodexAuthContext(ctx, auth)
	var response pluginapi.CodexAuthRecoveryResponse
	if err = h.callCodexAuth(record, "CodexAuth.RecoverTask", func(provider pluginapi.CodexAuth) error {
		var errRecovery error
		response, errRecovery = provider.RecoverTask(ctx, pluginapi.CodexAuthRecoveryRequest{
			AuthIndex:     authIndex,
			Authorization: authorization,
			Status:        status,
			Body:          bytes.Clone(body),
		})
		return errRecovery
	}); err != nil {
		return false, err
	}
	return response.Retry, nil
}

func (h *Host) codexAuthForIndex(authIndex string) (*coreauth.Auth, capabilityRecord, error) {
	auth, err := h.authByIndex(authIndex)
	if err != nil {
		return nil, capabilityRecord{}, err
	}
	record, ok := h.codexAuthRecord(auth.Metadata)
	if !ok {
		return nil, capabilityRecord{}, fmt.Errorf("no Codex auth plugin matches auth_index %s", strings.TrimSpace(authIndex))
	}
	return auth, record, nil
}

func (h *Host) codexAuthRecord(metadata map[string]any) (capabilityRecord, bool) {
	if h == nil {
		return capabilityRecord{}, false
	}
	for _, record := range h.activeRecords() {
		provider := record.plugin.Capabilities.CodexAuth
		if provider == nil || h.isPluginFused(record.id) {
			continue
		}
		matched := false
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					h.fusePlugin(record.id, "CodexAuth.Match", recovered)
				}
			}()
			matched = provider.Match(cloneAnyMap(metadata))
		}()
		if matched {
			return record, true
		}
	}
	return capabilityRecord{}, false
}

func (h *Host) callCodexAuth(record capabilityRecord, operation string, call func(pluginapi.CodexAuth) error) (err error) {
	provider := record.plugin.Capabilities.CodexAuth
	if h == nil || provider == nil || h.isPluginFused(record.id) || !h.recordCurrent(record) {
		return fmt.Errorf("codex auth plugin is unavailable")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			h.fusePlugin(record.id, operation, recovered)
			err = fmt.Errorf("codex auth plugin failed")
		}
	}()
	return call(provider)
}
