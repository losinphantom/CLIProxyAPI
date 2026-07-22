package helps

import "context"

// CodexOutboundAuth is the final outbound authentication seam used by the
// Codex HTTP and websocket executors. Implementations own credential-specific
// lifecycle behavior; callers treat the returned authorization as opaque.
type CodexOutboundAuth interface {
	Match(authMetadata map[string]any) bool
	Authorization(ctx context.Context, authIndex string) (string, error)
	RecoverTask(ctx context.Context, authIndex, authorization string, status int, body []byte) (retry bool, err error)
}
