package core

import (
	"crypto/sha256"
	"encoding/base64"
	"slices"

	"github.com/vektah/gqlparser/v2/ast"
)

// SSHFSVolume is a persistent volume with a globally scoped identifier.
type SSHFSVolume struct {
	Keys []string
}

func (*SSHFSVolume) Type() *ast.Type {
	return &ast.Type{
		NamedType: "SSHFSVolume",
		NonNull:   true,
	}
}

func (*SSHFSVolume) TypeDescription() string {
	return "A directory whose contents persist across runs."
}

func NewSSHFSVolume(keys ...string) *SSHFSVolume {
	return &SSHFSVolume{Keys: keys}
}

func (cache *SSHFSVolume) Clone() *SSHFSVolume {
	cp := *cache
	cp.Keys = slices.Clone(cp.Keys)
	return &cp
}

// Sum returns a checksum of the cache tokens suitable for use as a cache key.
func (cache *SSHFSVolume) Sum() string {
	hash := sha256.New()
	for _, tok := range cache.Keys {
		_, _ = hash.Write([]byte(tok + "\x00"))
	}

	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}
